
from flask import Flask, request, redirect, session, url_for

from oauth2client.client import OAuth2Credentials

### IMPORTANT ###
# This example app stores the user's Gloebit credential in the default
# Flask session.  Never do that in a real app!  Store it someplace secure.

import gloebit

app = Flask(__name__)

# For the application's secret key, do following commands and replace None
# below with the string.  And then never let anyone know the key.
# >>> import os
# >>> os.urandom(24)
app.secret_key = None

# Cut-and-paste these from Gloebit Merchant Tools page.  Optionally, you
# can put them in a client secrets JSON file and provide the path to that
# file.
CLIENT_KEY = ''
CLIENT_SECRET = ''

# For single-user simplicity, use a global merchant object.
MERCHANT = gloebit.Merchant(
    gloebit.Client_Secrets(CLIENT_KEY, CLIENT_SECRET, _sandbox=True),
    secret_key=app.secret_key)

@app.route('/')
def index():
    return '''
        <h2>Gloebit Flask Example Portal</h2>
        <a href='%s'>Enter</a>.
    ''' % url_for('login')

@app.route('/login')
def login():
    session.pop('username', None)
    redirect_uri = url_for('gloebit_callback', _external=True)
    return redirect(MERCHANT.user_authorization_url(redirect_uri=redirect_uri))

@app.route('/gloebit_callback')
def gloebit_callback():
    """Exchange code for credential.

    This example stores the credential in the default Flask session.  Do
    not do that in a real system!  Store it someplace secure instead.
    """
    credential = MERCHANT.exchange_for_user_credential(request.args)
    session['credential'] = credential.to_json()

    # Merchant scope includes 'id'.  Grab user's Gloebit username.
    gbinfo = MERCHANT.user_info(credential)
    session['username'] = gbinfo['name']

    return redirect(url_for('merchant'))

@app.route('/merchant')
def merchant():
    if 'msg' in request.args:
        message = request.args['msg']
    else:
        message = "No activity yet"
    return '''
        <h1>Gloebit Flask Example</h1>
        <h2>Welcome, %s.</h2>
        <form action="%s" method="post">
          <input type="hidden" name="size" value="small" />
          <input type="submit" value="Purchase small item" />
        </form>
        <p>%s.</p>
        <p><a href="/">Leave</a></p>
        ''' % (session['username'], url_for('purchase'), message)

@app.route('/purchase', methods=['POST'])
def purchase():
    item = request.form['size'] + " item"
    price = 1
    credential = OAuth2Credentials.from_json(session['credential'])
    MERCHANT.purchase(credential, item, price)
    return redirect(url_for('merchant', **{'msg': "You bought a " + item}))

if __name__ == "__main__":
    app.run(debug=True)
