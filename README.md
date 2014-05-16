python-django-gloebit
=====================

### Python module for accessing [Gloebit](http://docs.gloebit.com/)'s API
#### Plus, an example Django application using the Gloebit module.

The Gloebit python module supports many of the Gloebit user endpoints.
All user endpoints require an access token that the application must first acquire.

The Gloebit python module supports using OAuth 2.0 authorization code grant type for acquiring access tokens.  In this OAuth 2.0 flow, your application (the OAuth client) requests an authorization code for a user (the OAuth resource owner) from the Gloebit server (the OAuth authorization server), Gloebit requests and acquires authorization from the user, and sends an authorization code, if approved, to your application via a callback.  When called back, your application uses the code to get an access token from Gloebit for the user's resources.  Your application then uses the access token with the Gloebit server (the OAuth resource server) via the endpoints.

### Setting up Gloebit Python Module

Start by putting gloebit.py somewhere in your module search path, and
then import it into your application.

As a Gloebit merchant, you have an OAuth client key and an OAuth client secret.  They are available on your Gloebit Merchant Tools page.  Cut-and-paste them into your application or into an oauth2client client secrets JSON file and use them to create a Client_Secrets object.  (See the Django Gloebit example for how to use a client secrets file.)

```python
    # OAuth client key and secret from Gloebit Merchant Tools page
    MERCHANT_KEY = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    MERCHANT_SECRET = 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'

    CLIENT_SECRETS = gloebit.Client_Secrets(MERCHANT_KEY, MERCHANT_SECRET,
                                            _sandbox=True)
```

Next, create your Merchant object that will provide your Gloebit API.  Provide a scope specifying which endpoints you need to access, default is 'id' and 'transact'.  Your application's secret key is necessary to generate a 'state' nonce (in the authorization request) for CSRF detection.

```python
    MERCHANT = gloebit.Merchant(CLIENT_SECRETS, scope='id balance transact',
                                secret_key=your_app_secret_key)
```

gloebit.Merchant API
====================

### user_authorization_url

```python
    user_authorization_url(user=None, redirect_uri=None)
```

Returns the URL to initiate a Gloebit authorization request.  The first step in acquiring a Gloebit access token for a user is to redirect the user to this URL.  Redirecting the user to it will lead to a Gloebit login page (if necessary) and a merchant-approval page.  When the user approves your merchant access, Gloebit will redirect the user to your application's redirect URI with the authorization code attached as a query argument.  Handling this callback is the second step in acquiring the access token (see exchange_for_user_credential below).

You can provide your application's redirect URI with this call or when creating your Merchant object.  This method provides the optional redirect_uri argument in case your application framework cannot determine the absolute URI when the modules are initialized.  Note that the redirect URI must be absolute due to the authorization URL redirect to a Gloebit server.

The user argument is necessary (along with your application's secret key when creating the Merchant object) to add a 'state' nonce to the authorization URL for CSRF detection.  It is your application's name (or uuid) for the user.  Your applciation can get the user's Gloebit name (for your merchant account) after acquiring an access token--see user_info below.

### exchange_for_user_credential

```python
    exchange_for_user_credential(query_args, user=None)
```

Exchanges the Gloebit auhtorization code returned to the redirect URI for the user's Gloebit credential and returns the credential.  The code is sent as a query parameter, as is the 'state' nonce for CSRF detection.  Pass the query dictionary to this method.

If query_args includes a 'state' value, the method verifies it against the application's secret key and user.  The user passed to this method must match the user_authorization_url user.

### user_info

```python
    user_info(credential)
```

Can be invoked only if 'id' is in your merchant scope.

Returns a dictionary of Gloebit user information for the user.  Requires the user credential acquired via the 2-step OAuth 2.0 flow.

The dictionary contains 'id', 'name', and 'params' values.  The 'id' is the user Gloebit UUID and the 'name' is the user's selected name for your application.

### user_balance

```python
    user_balance(credential)
```

Can be invoked only if 'balance' is in your merchant scope.

Returns a float of the user's Gloebit balance.  Requires the user credential acquired via the 2-step OAuth 2.0 flow.

### purchase_item

```python
    purchase_item(credential, item, item_price, item_quantity=1, username=None)
```

Can be invoked only if 'transact' is in your merchant scope.

Requests a transaction for an application-named item (as opposed to a merchant-named product in the Gloebit system, see below) of item_quantity number at item_price gloebits.  Requires the user credential acquired via the 2-step OAuth 2.0 flow.  Also requires sufficient user balance.

A username is required if 'id' is not in your merchant scope, otherwise the user's merchant name will be used.  The username shows up in the merchant transaction log for the purchase.

Refer to the method document string for exceptions purchase_item can raise.

### purchase_product

```python
    purchase_product(credential, product, product_quantity=1, username=None)
```

Can be invoked only if 'transact' is in your merchant scope.

Requests a transaction for a merchant-named product (as opposed to an item named on-the-fly by your application, see above) of product_quantity number.  (You set the price on your Merchant Products Gloebit page.)  Requires the user credential acquired via the 2-step OAuth 2.0 flow.  Also requires sufficient user balance.

A username is required if 'id' is not in your merchant scope, otherwise the user's merchant name will be used.  The username shows up in the merchant transaction log for the purchase.

Refer to the method document string for exceptions purchase_product can raise.

Gloebit Django Example
======================
