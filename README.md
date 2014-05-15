python-django-gloebit
=====================

### Python module for accessing [Gloebit](http://docs.gloebit.com/)'s API and an example Django application using the Gloebit module.

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

Next, create your Merchant object that will provide your Gloebit API.  Your application's secret key is necessary to generate a 'state' nonce (in the authorization request) for CSRF detection.

```python
    MERCHANT = gloebit.Merchant(CLIENT_SECRETS, secret_key=your_app_secret_key)
```

gloebit.Merchant API
====================

### user_authorization_url

```python
    user_authorization_url(user=None, redirect_uri=None)
```

Returns the URL to initiate a Gloebit authorization request.  The first step in acquiring a Gloebit access token for a user is to redirect the user to this URL.  Redirecting the user to it will lead to a Gloebit login page (if necessary) and a merchant-approval page.  When the user approves your merchant access, Gloebit will redirect the user to your application's redirect URI with the authorization code attached as a query argument.  Handling this callback is the second step in acquiring the access token (see exchange_for_user_credential below).

A user argument is necessary (along with your application's secret key when creating the Merchant object) to add a 'state' nonce to the URL for CSRF detection.
