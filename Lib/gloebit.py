"""Module for handling Gloebit merchant interactions.

Interactions are handled by Merchant class objects, one object per merchant.

Merchant object initialization requires:
  ClientSecrets: Object holding merchant's client secrets.  Created
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
  3) Create Merchant object using the ClientSecrets object.
  4) Per-user:
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
import urllib
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
GLOEBIT_OAUTH2_COND_AUTH_URI = 'https://%s/oauth2/conditional-authorize'
GLOEBIT_OAUTH2_TOKEN_URI = 'https://%s/oauth2/access-token'
GLOEBIT_USER_URI = 'https://%s/user/'
GLOEBIT_VISIT_URI = 'https://%s/purchase/'
GLOEBIT_BALANCE_URI = 'https://%s/balance/'
GLOEBIT_CHARACTERS_URI = 'https://%s/get-characters/'
GLOEBIT_CREATE_CHARACTER_URI = 'https://%s/create-character/'
GLOEBIT_UPDATE_CHARACTER_URI = 'https://%s/update-character/'
GLOEBIT_DELETE_CHARACTER_URI = 'https://%s/delete-character/'
GLOEBIT_TRANSACT_URI = 'https://%s/transact/'
GLOEBIT_USER_PRODUCTS_URI = 'https://%s/get-user-products/'
GLOEBIT_USER_CONSUME_URI = 'https://%s/consume-user-product/%s/%s/'
GLOEBIT_USER_GRANT_URI = 'https://%s/grant-user-product/%s/%s/'
GLOEBIT_CHARACTER_PRODUCTS_URI = 'https://%s/get-character-products/%s/'
GLOEBIT_CHARACTER_CONSUME_URI = 'https://%s/consume-character-product/%s/%s/%s/'
GLOEBIT_CHARACTER_GRANT_URI = 'https://%s/grant-character-product/%s/%s/%s/'

CHECK_SSL_CERT = False

class Error(Exception):
    """Base error for this module."""

class CrossSiteError(Error):
    """XSRF state check in authorization failed."""

class BadRequestError(Error):
    """Response error from Gloebit not 200.  Code returned in string."""

class GloebitScopeError(Error):
    """Tried to invoke a Gloebit method not in the merchant's scope."""

class AccessTokenError(Error):
    """Error using access token (revoked or expired), reauthorize."""

class UserInfoError(Error):
    """Error trying to lookup Gloebit user info."""

class UserNameRequiredError(Error):
    """Error due to missing user name when 'id' is not in scope."""

class BalanceAccessError(Error):
    """Error trying to retrieve a Gloebit user's balance."""

class ProductsAccessError(Error):
    """Error trying to retrieve a Gloebit user's product inventory or
    consume a Gloebit user's products."""

class CharacterAccessError(Error):
    """Error trying to retrieve a Gloebit user's character list"""

class TransactError(Error):
    """Base error for Gloebit Transact errors."""

class TransactRequestError(TransactError):
    """HTTP status error for Gloebit transact request."""

class TransactFailureError(TransactError):
    """Gloebit transact request was processed but returned success=False."""

class ClientSecrets(object):
    """Container for OAuth2 client secrets."""

    @util.positional(3)
    def __init__(self, client_id, client_secret,
                 redirect_uri=None, auth_uri=None, token_uri=None,
                 _sandbox=False):
        """Create a ClientSecrets.

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
    def from_file(filename, cache=None, redirect_uri=None, _sandbox=False):
        """Create a ClientSecrets from a clientsecrets JSON file.

        Very closely resembles oauth2client.client.flow_from_clientsecrets().
        """
        _client_type, client_info = \
                      clientsecrets.loadfile(filename, cache=cache)
        constructor_kwargs = {
            'redirect_uri': redirect_uri,
            'auth_uri': client_info['auth_uri'],
            'token_uri': client_info['token_uri'],
            '_sandbox': _sandbox,
        }
        return ClientSecrets(client_info['client_id'],
                             client_info['client_secret'],
                             **constructor_kwargs)

    @staticmethod
    @util.positional(0)
    def from_server(_sandbox=False):
        """Create a ClientSecrets via the Gloebit server.

        Not yet implemented.
        """
        pass

class Gloebit(object):
    """Handles tasks for Gloebit merchants."""

    @util.positional(2)
    def __init__(self, client_secrets,
                 scope='transact inventory character user',
                 redirect_uri=None, secret_key=None):
        """Create a Merchant that will use the given ClientSecrets.

        Args:
          client_secrets: ClientSecrets, Merchant's Gloebit secrets.
          scope: string, Space-separated set of Gloebit methods to request
            authorization for.
          redirect_uri: string, Absolute URL for application to handle
            Gloebit callback with code.  Overrides the redirect_uri from
            the ClientSecrets.
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
        self.user_uri = GLOEBIT_USER_URI % hostname
        self.visit_uri = GLOEBIT_VISIT_URI % hostname
        self.balance_uri = GLOEBIT_BALANCE_URI % hostname
        self.characters_uri = GLOEBIT_CHARACTERS_URI % hostname
        self.create_character_uri = GLOEBIT_CREATE_CHARACTER_URI % hostname
        self.update_character_uri = GLOEBIT_UPDATE_CHARACTER_URI % hostname
        self.delete_character_uri = GLOEBIT_DELETE_CHARACTER_URI % hostname
        self.transact_uri = GLOEBIT_TRANSACT_URI % hostname
        self.flow = None

        self._hostname = hostname

    @util.positional(3)
    def ready_flow (self, redirect_uri, user):
        """ create oauth2 flow object """
        if redirect_uri is None:
            redirect_uri = self.redirect_uri
        self.flow = OAuth2WebServerFlow(self.client_id,
                                        self.client_secret,
                                        self.scope,
                                        redirect_uri=redirect_uri,
                                        auth_uri=self.auth_uri,
                                        token_uri=self.token_uri,
                                        revoke_uri=None)
        if user:
            self.flow.params['state'] = \
                xsrfutil.generate_token(self.secret_key, user)

    @util.positional(2)
    def _products_uri(self, character_id):
        """ return uri to use for consuming a product """
        if character_id:
            q_character_id = urllib.quote(character_id)
            return GLOEBIT_CHARACTER_PRODUCTS_URI % \
                   (self._hostname, q_character_id)
        return GLOEBIT_USER_PRODUCTS_URI % (self._hostname)


    @util.positional(4)
    def _consume_uri(self, character_id, product, count):
        """ return uri to use for consuming a product """
        q_product = urllib.quote(product)
        if character_id:
            q_character_id = urllib.quote(character_id)
            return GLOEBIT_CHARACTER_CONSUME_URI % \
                   (self._hostname, q_character_id, q_product, count)
        return GLOEBIT_USER_CONSUME_URI % (self._hostname, q_product, count)


    @util.positional(4)
    def _grant_uri(self, character_id, product, count):
        """ return uri to use for consuming a product """
        q_product = urllib.quote(product)
        if character_id:
            q_character_id = urllib.quote(character_id)
            return GLOEBIT_CHARACTER_GRANT_URI % \
                   (self._hostname, q_character_id, q_product, count)
        return GLOEBIT_USER_GRANT_URI % (self._hostname, q_product, count)


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

        self.ready_flow (redirect_uri, user)

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
        self.ready_flow (None, user)

        # Need better checks here.  If we have a secret key and a user, then
        # we need to expect a state and throw an error if we did not get one.
        #
        if user and 'state' in query_args:
            if not xsrfutil.validate_token(self.secret_key,
                                           query_args['state'],
                                           user):
                raise CrossSiteError

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        credential = self.flow.step2_exchange(query_args['code'], http=http)

        return credential

    @util.positional(2)
    def user_info(self, credential):
        """Use credential to retrieve Gloebit user information.

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).

        Returns:
          Dictionary containing following key-value pairs:
            id: Gloebit unique identifier for user.
            name: User-selected character name for your merchant app.
            params: I don't know yet...

        Raises:
          GloebitScopeError if 'user' not in Merchant's scope.
          BadRequestError if Gloebit returned any code other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          UserInfoError if Gloebit returned 200 status with False success and
            a failure reason other than access token error.
        """
        if "user" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self.user_uri,
            method='GET',
            headers={'Authorization': 'Bearer ' + access_token}
        )

        response = _success_check(resp, response_json, UserInfoError)

        return { 'id': response.get('id', None),
                 'name': response.get('full-name', None) }

    @util.positional(2)
    def user_balance(self, credential):
        """Use credential to retrieve Gloebit user balance.

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).

        Returns:
          User's balance as a float.

        Raises:
          GloebitScopeError if 'balance' not in Merchant's scope.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          BalanceAccessError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "balance" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self.balance_uri,
            method='GET',
            headers={'Authorization': 'Bearer ' + access_token}
        )

        response = _success_check(resp, response_json, BalanceAccessError)
        return response['balance']


    @util.positional(4)
    def purchase_item(self, credential, item, item_price,
                      item_quantity=1, username=None):
        """Use credential to buy untracked item at item_price via Gloebit.

        This method is for purchasing an item that the merchant has not
        added to the merchant's product list on Gloebit.  Thus, it requires
        the item description and price (in Gloebits).

        To purchase from the merchant's product list, use either
        purchase_user_product() or purchase_character_product().

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          item: string, Merchant's description of item being purchased.
          item_price: integer, Price in G$ for each item.
          item_quantity: integer, Number of items to purchase.
          username: string, Merchant's ID/name for purchaser.  If not given and
            'user' is in merchant's Gloebit scope, will look up user's name and
            use that in purchase request.  If not given and 'user' is not in
            merchant's Gloebit scope, an error will be raised.

        Returns:
          User's resulting balance as a float.  If 'balance' is not in
            Merchant's, balance will be None.

        Raises:
          GloebitScopeError if 'transact' not in merchant's scope.
          UserNameRequiredError if 'id' not in merchant's scope and no
            username provided.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          TransactFailureError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "transact" not in self.scope:
            raise GloebitScopeError

        if not username:
            if 'user' in self.scope.split():
                userinfo = self.user_info(credential)
                username = userinfo['name']
            else:
                raise UserNameRequiredError

        total_cost = item_price * item_quantity

        transaction = {
            'version':                     1,
            'id':                          str(uuid.uuid4()),
            'request-created':             int(time.time()),
            'asset-code':                  item,
            'asset-quantity':              item_quantity,
            'asset-enact-hold-url':        None,
            'asset-consume-hold-url':      None,
            'asset-cancel-hold-url':       None,
            'gloebit-balance-change':      total_cost,
            'gloebit-recipient-user-name': None,
            'consumer-key':                self.client_id,
            'username-on-consumer':        username,
        }

        access_token = credential.access_token

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self.transact_uri,
            method='POST',
            headers={'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json'},
            body=json.dumps(transaction),
        )

        response = _success_check(resp, response_json, TransactFailureError)

        return response.get('balance', None)

    @util.positional(3)
    def _get_products(self, credential, character_id=None):
        """Use credential to retrieve Gloebit user product inventory.

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          character_id: Gloebit ID for user's character.

        Returns:
          User's product inventory as a dictionary.

        Raises:
          GloebitScopeError if 'inventory' not in Merchant's scope.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          ProductsAccessError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "inventory" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True

        resp, response_json = http.request(
            uri=self._products_uri (character_id),
            method='GET',
            headers={'Authorization': 'Bearer ' + access_token}
        )

        response = _success_check(resp, response_json, ProductsAccessError)
        return response['products']


    @util.positional(2)
    def user_products(self, credential):
        """ list products associated with a gloebit user """
        return self._get_products(credential)

    @util.positional(3)
    def character_products(self, credential, character_id):
        """ list products associated with a gloebit user """
        return self._get_products(credential, character_id=character_id)

    @util.positional(3)
    def _purchase_product(self, credential, product,
                          product_quantity=1, character_id=None, username=None):
        """Use credential to buy product via Gloebit.

        This method is for purchasing a product that the merchant has added
        to the merchant's product list on Gloebit.

        To purchase an untracked item, use purchase_item().

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          product: string, Merchant's name for product being purchased.  Needs
            to match name on merchant products page.
          product_quantity: integer, Product quantity to purchase.
          character_id: Gloebit ID for user's character.
          username: string, Merchant's ID/name for purchaser.  If not given and
            'user' is in merchant's Gloebit scope, will look up user's name and
            use that in purchase request.  If not given and 'user' is not in
            merchant's Gloebit scope, an error will be raised.

        Returns:
          A tuple of the user's resulting balance as a float and the user's
            new product count after the purchase, as an int.  If 'balance'
            is not in Merchant's scope, balance will be None.  If 'inventory'
            is not in Merchant's scope, the count will be None.

        Raises:
          GloebitScopeError if 'transact' not in merchant's scope.
          UserNameRequiredError if 'id' not in merchant's scope and no
            username provided.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          TransactFailureError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "transact" not in self.scope:
            raise GloebitScopeError

        if not username:
            if 'user' in self.scope.split():
                userinfo = self.user_info(credential)
                username = userinfo['name']
            else:
                raise UserNameRequiredError


        transaction = {
            'version':                     1,
            'id':                          str(uuid.uuid4()),
            'request-created':             int(time.time()),
            'product':                     product,
            'product-quantity':            product_quantity,
            # 'asset-enact-hold-url':        None,
            # 'asset-consume-hold-url':      None,
            # 'asset-cancel-hold-url':       None,
            # 'gloebit-recipient-user-name': None,
            'consumer-key':                self.client_id,
            'character-id':                character_id,
            'username-on-consumer':        username,
        }

        access_token = credential.access_token

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self.transact_uri,
            method='POST',
            headers={'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json'},
            body=json.dumps(transaction),
        )

        response = _success_check(resp, response_json, TransactFailureError)

        balance = response.get('balance', None)
        remaining = response.get('product-count', None)
        return (balance, remaining)


    @util.positional(3)
    def purchase_user_product(self, credential, product,
                              product_quantity=1, username=None):
        """ purchase a product for a user """
        return self.purchase_product(credential, None, product,
                                     product_quantity, username)



    @util.positional(4)
    def purchase_character_product(self, credential, character_id, product,
                                   product_quantity=1, username=None):
        """ purchase a product for a character """
        return self.purchase_product(credential, character_id, product,
                                     product_quantity, username)



    @util.positional(4)
    def consume_product(self, credential, character_id, product,
                        product_quantity=1):
        """Use credential to consume user's product(s) via Gloebit.

        This method is for consuming (deleting) one or more of a product that
        the user previously purchased on Gloebit

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          product: string, Merchant's name for product being purchased.  Needs
            to match name on merchant products page.
          product_quantity: integer, Product quantity to purchase.

        Returns:
          User's new product count after consumption, as an int.

        Raises:
          GloebitScopeError if 'inventory' not in merchant's scope.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          ProductsAccessError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "inventory" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token
        transaction = {}

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self._consume_uri(character_id, product, product_quantity),
            method='POST',
            headers={'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json'},
            body=json.dumps(transaction),
        )

        response = _success_check(resp, response_json, ProductsAccessError)
        print "response: " + str(response)

        return response.get('product-count', None)


    @util.positional(4)
    def consume_user_product(self, credential, product, product_quantity=1):
        """ decrement product count for a user """
        return self.consume_product(credential, None, product,
                                    product_quantity)


    @util.positional(4)
    def consume_character_product(self, credential, character_id, product,
                                  product_quantity=1):
        """ decrement product count for a character """
        return self.consume_product(credential, character_id, product,
                                    product_quantity)



    @util.positional(4)
    def grant_product(self, credential, character_id,
                      product, product_quantity=1):
        """Use credential to grant user's product(s) via Gloebit.

        This method is for consuming (deleting) one or more of a product that
        the user previously purchased on Gloebit

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          product: string, Merchant's name for product being purchased.  Needs
            to match name on merchant products page.
          product_quantity: integer, Product quantity to purchase.

        Returns:
          User's new product count after consumption, as an int.

        Raises:
          GloebitScopeError if 'inventory' not in merchant's scope.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          ProductsAccessError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "inventory" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token
        transaction = {}

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self._grant_uri(character_id, product, product_quantity),
            method='POST',
            headers={'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json'},
            body=json.dumps(transaction),
        )

        response = _success_check(resp, response_json, ProductsAccessError)
        print "response: " + str(response)

        return response.get('product-count', None)


    @util.positional(4)
    def grant_user_product(self, credential, product, product_quantity=1):
        """ increment count of user product """
        return self.grant_product(credential, None,
                                  product, product_quantity)


    @util.positional(4)
    def grant_character_product(self, credential, character_id,
                                product, product_quantity=1):
        """ increment count of character product """
        return self.grant_product(credential, character_id,
                                  product, product_quantity)



    @util.positional(2)
    def user_characters(self, credential):
        """Use credential to retrieve Gloebit user character list.

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).

        Returns:
          List of user's characters, each is a dictionary.

        Raises:
          GloebitScopeError if 'character' not in Merchant's scope.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          CharacterAccessError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "character" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self.characters_uri,
            method='GET',
            headers={'Authorization': 'Bearer ' + access_token})

        response = _success_check(resp, response_json, CharacterAccessError)
        return response['characters']

    @util.positional(3)
    def create_character(self, credential, character):
        """Use credential to create Gloebit user character.

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          character: a dictionary that hold character parameters

        Returns:
          character dictionary

        Raises:
          GloebitScopeError if 'character' not in Merchant's scope.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          CharacterAccessError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "character" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token

        if character.get ('name', None) == None:
            raise CharacterAccessError('character must have "name" field')

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self.create_character_uri,
            method='POST',
            headers={'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json'},
            body=json.dumps(character))

        response = _success_check(resp, response_json, CharacterAccessError)
        return response['character']

    @util.positional(3)
    def update_character(self, credential, character):
        """Use credential to update Gloebit user character.

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          character: a dictionary that hold character parameters

        Returns:
          character dictionary

        Raises:
          GloebitScopeError if 'character' not in Merchant's scope.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          CharacterAccessError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "character" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token

        if character.get ('name', None) == None:
            raise CharacterAccessError('character must have "name" field')

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self.update_character_uri,
            method='POST',
            headers={'Authorization': 'Bearer ' + access_token,
                     'Content-Type': 'application/json'},
            body=json.dumps(character))

        response = _success_check(resp, response_json, CharacterAccessError)
        return response['character']


    @util.positional(3)
    def delete_character(self, credential, character_id):
        """Use credential to delete a user's character

        Args:
          credential: Oauth2Credentials object, Gloebit authorization credential
            acquired from 2-step authorization process (oauth2).
          character_id: uuid of character

        Returns:
          True

        Raises:
          GloebitScopeError if 'character' not in Merchant's scope.
          BadRequestError if Gloebit returned any HTTP status other than 200.
          AccessTokenError if access token has expired or is otherwise
            invalid.
          CharacterAccessError if Gloebit returned 200 HTTP status with False
            success and a failure reason other than access token error.
        """
        if "character" not in self.scope:
            raise GloebitScopeError

        access_token = credential.access_token

        http = httplib2.Http()
        if not CHECK_SSL_CERT:
            http.disable_ssl_certificate_validation = True
        resp, response_json = http.request(
            uri=self.delete_character_uri + character_id,
            method='GET',
            headers={'Authorization': 'Bearer ' + access_token})

        response = _success_check(resp, response_json, CharacterAccessError)
        return response['success']



def _success_check(resp, response_json, exception):
    """Check response and body for success or failure.

    Any response code other than 200 is considered an error.  Probably
    should change that to any 4xx or 5xx response code being an error.

    If response code is 200, then extract the JSON from the body and
    look for a 'success' field.  If exists and not True, raise an error.

    Args:
      resp: dictionary of response headers(?).
      response_json: JSON from response body.
      exception: exception to raise for unknown failure reasons.

    Returns:
      Response dictionary from response_json.

    Raises:
      BadRequestError if Gloebit returned any HTTP status other than 200.
      AccessTokenError if access token has expired or is otherwise invalid.
      exception if Gloebit returned 200 HTTP status with False success and a
        failure reason other than access token error.
    """
    if resp.status != 200:
        raise BadRequestError("Gloebit returned %s status!" % str(resp.status))

    response = json.loads(response_json)

    if 'success' in response.keys():
        if response['success'] != True:
            if response['reason'] == 'unknown token2':
                raise AccessTokenError
            else:
                raise exception(response['reason'])

    return response
