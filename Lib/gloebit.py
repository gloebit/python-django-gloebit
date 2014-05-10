"""Module for handling client (merchant) interactions with Gloebit.

Interactions are handled by Merchant class objects, one object per merchant.

Merchant object initialization requires:
  Client_Secrets: Object holding merchant's client secrets.  Created
    with either the client key and secret (from Gloebit Merchant Tools
    page) or a client secrets JSON file (containing same info and more).
  Redirect URI: URI for callback from Gloebit server with credential
    code following user authorization via Gloebit's authorization URI.

A Merchant object provides the following methods:
  user_authorization_url: Provides URL for redirecting user agent to
    get user's authorization.  After successful authorization, the
    user agent will be redirected to the Redirect URI.
  exchange_for_user_credential: Exchanges code (from query parameters
    attached to Redirect URI) for user credential from Gloebit server.
    The user credential contains the resource access token.
  user_info: Returns dictionary of Gloebit user information.  Requires
    user credential (from authorization steps).  Also, merchant must
    have 'id' in its scope.
  purchase: Performs a Gloebit purchase.  Requires user credential (from
    authorization steps), an item description, and an item price.  Also,
    merchant must have 'transact' in its scope.

Typical flow for single-merchant service:
  1) Import gloebit module.
  2) Create Client_secrets object.
  2) Create Merchant object using the Client_Secrets object.
  3) Per-user:
     a) Redirect user agent to Gloebit authorization URL (get URL
        from Merchant object).
     b) When Gloebit redirects user agent to redirect URI, give
        query args to Merchant object to exchange for user credential.
     c) Store user credential.
     d) Use credential to look up user info, make purchases, etc.
"""

### TODO
###   * Replace all response returns with exception raises.
###   * Params passed backed when getting user info, what are they?
###   * Improve XSRF checking when exchanging code for credential.

import httplib2
import json
import uuid
import time

from urlparse import urlparse

from oauth2client import clientsecrets, xsrfutil
from oauth2client.client import OAuth2WebServerFlow

from oauth2client import util

GLOEBIT_SERVER = 'www.gloebit.com'
GLOEBIT_SANDBOX = 'sandbox.gloebit.com'
GLOEBIT_OAUTH2_AUTH_URI = 'https://%s/oauth2/authorize'
GLOEBIT_OAUTH2_TOKEN_URI = 'https://%s/oauth2/access-token'
GLOEBIT_ID_URI = 'https://%s/id/'
GLOEBIT_TRANSACT_URI = 'https://%s/transact/'

class Error(Exception):
    """Base error for this module."""

class CrossSiteError(Error):
    """XSRF state check in authorization failed."""

class BadRequestError(Error):
    """Response error from Gloebit not 200.  Code returned in string."""

class AccessTokenError(Error):
    """Error using access token (revoked or expired), reauthorize."""

class UserInfoError(Error):
    """Error trying to lookup Gloebit user info."""

class UserNameRequiredError(Error):
    """Error due to missing user name when 'id' is not in scope."""

class TransactError(Error):
    """Base error for Gloebit Transact errors."""

class TransactRequestError(TransactError):
    """HTTP status error for Gloebit transact request."""

class TransactFailureError(TransactError):
    """Gloebit transact request was processed but returned success=False."""

class Client_Secrets(object):
    """Container for OAuth2 client secrets."""

    @util.positional(3)
    def __init__(self, client_id, client_secret,
                 redirect_uri=None, auth_uri=None, token_uri=None,
                 _sandbox=False):
        """Create a Client_Secrets.

        Args:
          client_id: string, Merchant's OAuth key for Gloebit account.  Cut
            and paste it from Merchant Tools page into the code using this
            method directly (or put into a secrets JSON file).
          client_secret: string, Merchant's OAuth secret for Gloebit account.
            Cut and paste it along with the key.
          redirect_uri: string, Absolute URL for application to handle
            Gloebit callback with code.
          auth_uri: string, URL for Gloebit authorization method.
          token_uri: string, URL for Gloebit access token method.
          _sandbox: Boolean, Set to True to use sandbox testing server.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_uri = auth_uri
        self.token_uri = token_uri

        if _sandbox:
            self.auth_uri = GLOEBIT_OAUTH2_AUTH_URI % GLOEBIT_SANDBOX
            self.token_uri = GLOEBIT_OAUTH2_TOKEN_URI % GLOEBIT_SANDBOX
        else:
            if auth_uri is None:
                self.auth_uri = GLOEBIT_OAUTH2_AUTH_URI % GLOEBIT_SERVER
            if token_uri is None:
                self.token_uri = GLOEBIT_OAUTH2_TOKEN_URI % GLOEBIT_SERVER

    @staticmethod
    @util.positional(1)
    def from_file(filename, cache=None, redirect_uri=None,_sandbox=False):
        """Create a Client_Secrets from a clientsecrets JSON file.

        Very closely resembles oauth2client.client.flow_from_clientsecrets().
        """
        client_type, client_info = clientsecrets.loadfile(filename, cache=cache)
        constructor_kwargs = {
            'redirect_uri': redirect_uri,
            'auth_uri': client_info['auth_uri'],
            'token_uri': client_info['token_uri'],
            '_sandbox': _sandbox,
        }
        return Client_Secrets(client_info['client_id'],
                              client_info['client_secret'],
                              **contructor_kwargs)

    @staticmethod
    @util.positional(0)
    def from_server(_sandbox=False):
        """Create a Client_Secrets via the Gloebit server.

        Not yet implemented.
        """
        pass
        
class Merchant(object):
    """Handles tasks for Gloebit merchants."""

    @util.positional(2)
    def __init__(self, client_secrets, scope='id transact',
                 redirect_uri=None, secret_key=None):
        """Create a Merchant that will use the given Client_Secrets.

        Args:
          client_secrets: Client_Secrets, Merchant's Gloebit secrets.
          scope: string, Space-separated set of Gloebit methods to request
            authorization for.
          redirect_uri: string, Absolute URL for application to handle
            Gloebit callback with code.  Overrides the redirect_uri from
            the Client_Secrets.
          secret_key: string, Application's secret key; used for cross-site
            forgery prevention, if provided.

        Returns:
          A Merchant ready for user authorization and Gloebit methods.
        """
        self.client_secrets = client_secrets
        self.client_id = client_secrets.client_id
        self.client_secret = client_secrets.client_secret
        self.auth_uri = client_secrets.auth_uri
        self.token_uri = client_secrets.token_uri
        self.scope = scope

        self.redirect_uri = client_secrets.redirect_uri
        if redirect_uri is not None:
            self.redirect_uri = redirect_uri

        self.secret_key = secret_key

        parsed_auth_uri = urlparse(self.auth_uri)
        hostname = parsed_auth_uri.hostname
        self.id_uri = GLOEBIT_ID_URI % hostname
        self.transact_uri = GLOEBIT_TRANSACT_URI %hostname

    @util.positional(1)
    def user_authorization_url(self, user=None, redirect_uri=None):
        """Get the Gloebit URL to initiate oauth2 authorization.

        Args:
          redirect_uri: string, Mechant server's URL that handles the callback
            from the Gloebit authorization server.  This will override the
            URI provided when creating the Merchant object, but only for the
            current authorization flow.

        Notes:
          1) Currently supports http URLs only.  Thus, a non-web-based
             application's callback URI might not work.
        """
        if redirect_uri is None:
            redirect_uri = self.redirect_uri

        self.flow = OAuth2WebServerFlow(self.client_id,
                                        self.client_secret,
                                        self.scope,
                                        redirect_uri=redirect_uri,
                                        auth_uri=self.auth_uri,
                                        token_uri=self.token_uri,
                                        revoke_uri=None)

        if user and self.secret_key is not None:
            self.flow.params['state'] = \
                xsrfutil.generate_token(self.secret_key, user)

        return self.flow.step1_get_authorize_url()

    @util.positional(2)
    def exchange_for_user_credential(self, query_args, user=None):
        """Exchange params from Gloebit authorization for Gloebit credential.

        Accessing the Gloebit authorization URL results in a redirection (after
        the user authorizes access) to the merchant's redirect URI, with a code
        provided as a query-arg.  This function provides the second step of the
        authorization by exchanging the code for a Gloebit credential.

        Args:
          query_arg: dictionary, Query arguments from redirection request.

        Returns:
          An Oauth2Credentials object for authorizing Gloebit requests.
        """

        # Need better checks here.  If we have a secret key and a user, then
        # we need to expect a state and throw an error if we did not get one.
        #
        if user and 'state' in query_args:
            if not xsrfutil.validate_token(self.secret_key,
                                           query_args['state'],
                                           user):
                raise CrossSiteError

        # The Merchant object will not have a flow if the server is
        # restarted and the oauth2 callback is the first access!
        #
        credential = self.flow.step2_exchange(query_args['code'])

        return credential

    @util.positional(2)
    def user_info(self, credential):
        """Use credential to retreive Gloebit user information.

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).

        Returns:
          dictionary containing following key-value pairs:
            id: Gloebit unique identifier for user.
            name: User-selected character name for your merchant app.
            params: I don't know yet...

        Raises:
          UserInfoError if the request returns a status other than 200.
        """
        if "id" not in self.scope:
            return None

        access_token = credential.access_token

        # Should the Server object handle the http request instead of
        # getting the uri from it and handling the request here?
        http = httplib2.Http()
        resp, response_json = http.request(
            uri=self.id_uri,
            method='GET',
            headers={'Authorization': 'Bearer ' + access_token}
        )

        response = _success_check(resp, response_json, UserInfoError)

        return { 'id': response.get('id', None),
                 'name': response.get('name', None),
                 'params': response.get('params', None), }

    @util.positional(4)
    def purchase(self, credential, item, item_price,
                 item_quantity=1, username=None):
        """Use credential to buy item at item_price via Gloebit.

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          item: string, Merchant's description of item being purchased.
          item_price: integer, Price in G$ for each item.
          item_quantity: integer, Number of items to purchase.
          username: string, Merchant's ID/name for purchaser.  If not given and
            'id' is in merchant's Gloebit scope, will look up user's name and
            use that in purchase request.  If not given and 'id' is not in
            merchant's Gloebit scope, an error will be raised.

        Raises:
          UserNameRequiredError if 'id' not in merchant's scope and no
            username provided.
        """
        if not username:
            if 'id' in self.scope.split():
                userinfo = self.user_info(credential)
                username = userinfo['name']
            else:
                raise UserNameRequiredError

        transaction = {
            'version':                     1,
            'id':                          str(uuid.uuid4()),
            'request-created':             int(time.time()),
            'asset-code':                  item,
            'asset-quantity':              item_quantity,
            'asset-enact-hold-url':        None,
            'asset-consume-hold-url':      None,
            'asset-cancel-hold-url':       None,
            'gloebit-balance-change':      item_price,
            'gloebit-recipient-user-name': None,
            'consumer-key':                self.client_id,
            'merchant-user-id':            username,
        }

        access_token = credential.access_token

        # Should the Server object handle the http request instead of
        # getting the uri from it and handling the request here?
        http = httplib2.Http()
        resp, response_json = http.request(
            uri=self.transact_uri,
            method='POST',
            headers={'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json'},
            body=json.dumps(transaction),
        )

        _success_check(resp, response_json, TransactFailureError)


def _success_check(resp, response_json, exception):
    """Check response and body for success or failure.

    Any response code other than 200 is considered an error.  Probably
    should change that to any 4xx or 5xx response code being an error.

    If response code is 200, then extract the JSON from the body and
    look for a 'success' field.  If exists and not True, raise an error.

    Args:
      resp: dictionary of response headers(?).
      response_json: JSON from response body

    Returns:
          
    Raises
    """
    if resp.status != 200:
        raise BadRequestError("Gloebit returned " + str(resp.status) + " status!")

    response = json.loads(response_json)
            
    if 'success' in response.keys():
        if response['success'] != True:
            if response['reason'] == 'unknown token2':
                raise AccessTokenError
            else:
                raise exception(response['reason'])

    return response
