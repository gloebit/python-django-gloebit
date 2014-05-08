"""Module for handling client (merchant) interactions with Gloebit.

Interactions are handled by Merchant class objects, one object per merchant.

Merchant object initialization requires:
  Secrets file: Pathname to a client secrets JSON file containing the
    merchant's client ID and client secret (from the Gloebit Merchant
    Tools page) and the Gloebit server's authorization and token URIs.
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
  2) Create Merchant object (with secrets file and redirect URI).
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
from oauth2client.client import flow_from_clientsecrets

from oauth2client import util

class Error(Exception):
    """Base error for this module."""

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

class _Server(object):
    """Provides Gloebit server URIs.

    The object extracts the server address from the client's secrets file,
    which holds the Gloebit authorization and token URIs.  It creates the
    resource URIs from that address.

    If we create a mechanism for pulling a client secrets file from the
    server, this object's functionality will reverse, instead creating the
    URIs from a provided hostname.
    """

    def __init__(self, secrets_file):
        client_type, client_info = clientsecrets.loadfile(secrets_file)
        auth_uri = client_info['auth_uri']
        parsed_auth_uri = urlparse(auth_uri)

        self.hostname = parsed_auth_uri.hostname

    def id_uri(self):
        return 'https://' + self.hostname + '/id/'

    def transact_uri(self):
        return 'https://' + self.hostname + '/transact/'


class Merchant(object):
    """Handles tasks for Gloebit merchants."""

    @util.positional(3)
    def __init__(self, secrets_file, redirect_uri,
                 scope='id transact', secret_key=None):

        self.server = _Server(secrets_file)

        self.secrets_file = secrets_file
        self.redirect_uri = redirect_uri
        self.scope = scope

        self.secret_key = secret_key

        client_type, client_info = clientsecrets.loadfile(secrets_file)

        self._client_id = client_info['client_id']

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
        if not redirect_uri:
            redirect_uri = self.redirect_uri

        self.flow = flow_from_clientsecrets(self.secrets_file,
                                            self.scope,
                                            redirect_uri=redirect_uri)

        if user and self.secret_key:
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
                return HttpResponseBadRequest()

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
            uri=self.server.id_uri(),
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
            'consumer-key':                self._client_id,
            'merchant-user-id':            username,
        }

        access_token = credential.access_token

        # Should the Server object handle the http request instead of
        # getting the uri from it and handling the request here?
        http = httplib2.Http()
        resp, response_json = http.request(
            uri=self.server.transact_uri(),
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
