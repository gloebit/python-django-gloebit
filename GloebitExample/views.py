
import os
import uuid
from functools import wraps

from oauth2client.django_orm import Storage

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.views.decorators.http import require_POST

from mysite import settings

# from gloebitexample.models import CredentialModel
from models import CredentialModel

import gloebit

CLIENT_SECRETS = os.path.join(os.path.dirname(__file__),
                              '..',
                              'client_secrets.json')

MERCHANT = gloebit.Gloebit(gloebit.ClientSecrets.from_file(CLIENT_SECRETS),
                           scope='user balance inventory transact',
                           secret_key=settings.SECRET_KEY)

# Create your views here.

def gloebit_required(function):
    """
    Wrapper 
    """
    @wraps(function)
    def wrapper(request, *args, **kwargs):
        username = request.session.get('username',None)
        if username is not None:
            storage = Storage(CredentialModel, 'user', username, 'credential')
            credential = storage.get()
            if credential is not None:
                return function(request, *args, **kwargs)
        rel_uri = reverse('GloebitEx:gloebit_callback')
        kwargs = { 'redirect_uri': request.build_absolute_uri(rel_uri) }
        auth_uri = MERCHANT.user_authorization_url(**kwargs)
        return HttpResponseRedirect(auth_uri)
    return wrapper

@gloebit_required
def index(request):
    context = {
        'username' : request.session.get('username', None),
        'balance' : request.session.get('balance', 0.0),
        'products' : request.session.get('inventory', None),
        'message' : request.session.get('message', None),
    }
    request.session['message'] = None
    return render(request, 'GloebitEx/index.html', context)

@require_POST
@gloebit_required
def purchase_item(request):
    action = request.POST['action']
    item = action[6:]
    size = item.split()[0]
    if size == "tiny":
        price = 1
    elif size == "small":
        price = 3
    elif size == "big":
        price = 10
    else:
        request.session['message'] = "Can't %s?!?" % action
        return HttpResponseRedirect(reverse('GloebitEx:index'))

    username = request.session.get('username', None)
    storage = Storage(CredentialModel, 'user', username, 'credential')
    credential = storage.get()

    try:
        balance = MERCHANT.purchase_item(credential, item, price)
        request.session['balance'] = balance
    except gloebit.AccessTokenError:
        request.session['message'] = "Stale token!  Logout and enter again"
    else:
        request.session['message'] = "You bought a %s." % item

    return HttpResponseRedirect(reverse('GloebitEx:index'))

@require_POST
@gloebit_required
def product_action(request):
    if 'product' not in request.POST:
        request.session['message'] = "You did not pick a product!"
        return HttpResponseRedirect(reverse('GloebitEx:index'))

    product = request.POST['product']

    username = request.session.get('username', None)
    storage = Storage(CredentialModel, 'user', username, 'credential')
    credential = storage.get()

    try:
        if request.POST['action'] == "Purchase product":
            balance, count = MERCHANT.purchase_product(credential, product)
            request.session['balance'] = balance
            request.session['inventory'][product] = count
            request.session['message'] = "You bought a %s." % product
        else:
            count = MERCHANT.consume_product(credential, product)
            request.session['inventory'][product] = count
            request.session['message'] = "You consumed a %s." % product
    except gloebit.AccessTokenError:
        request.session['message'] = "Stale token!  Logout and enter again"
    except gloebit.TransactFailureError as e:
        if str(e) == "canceled":
            request.session['message'] = "Purchase canceled.  Try consuming."
        else:
            request.session['message'] = "Purchase canceled: " + str(e)
    except gloebit.ProductsAccessError as e:
        if str(e) == "user doesn't have enough":
            request.session['message'] = \
                "You don't have a %s to consume!" % product
        else:
            request.session['message'] = "Product failure: " + str(e)

    return HttpResponseRedirect(reverse('GloebitEx:index'))

def gloebit_callback(request):
    credential = MERCHANT.exchange_for_user_credential(request.GET)

    if 'user' in MERCHANT.scope:
        gbinfo = MERCHANT.user_info(credential)
        print "gbinfo: %s\n" % str(gbinfo)
        username = gbinfo['name']
        request.session['username'] = username
    else:
        username = str(uuid.uuid4())
        request.session['username'] = username

    print "user: %s\n" %username
    storage = Storage(CredentialModel, 'user', username, 'credential')
    storage.delete()  # Get rid of stale token, if any
    storage.put(credential)

    inventory = MERCHANT.user_products(credential)
    request.session['inventory'] = inventory

    return HttpResponseRedirect(reverse('GloebitEx:index'))

def logout(request):
    username = request.session.get('username', None)
    if username is not None:
        storage = Storage(CredentialModel, 'user', username, 'credential')
        storage.delete()
        request.session['username'] = None
    return HttpResponseRedirect('/')
