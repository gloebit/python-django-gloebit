
import os
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

MERCHANT = gloebit.Merchant(gloebit.Client_Secrets.from_file(CLIENT_SECRETS),
                            scope='id balance transact',
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
        'message' : request.session.get('message', None),
    }
    request.session['message'] = None
    return render(request, 'GloebitEx/index.html', context)

@require_POST
@gloebit_required
def purchase_item(request):
    item = request.POST['size'] + " item"
    price = 1

    username = request.session.get('username', None)
    storage = Storage(CredentialModel, 'user', username, 'credential')
    credential = storage.get()

    try:
        balance = MERCHANT.purchase_item(credential, item, price)
        request.session['balance'] = balance
    except gloebit.AccessTokenError as e:
        request.session['message'] = "Stale token!  Logout and enter again"
    else:
        request.session['message'] = "You bought a " + item

    return HttpResponseRedirect(reverse('GloebitEx:index'))

def gloebit_callback(request):
    credential = MERCHANT.exchange_for_user_credential(request.GET)

    gbinfo = MERCHANT.user_info(credential)
    username = gbinfo['name']
    request.session['username'] = username

    storage = Storage(CredentialModel, 'user', username, 'credential')
    storage.put(credential)

    return HttpResponseRedirect(reverse('GloebitEx:index'))

def logout(request):
    username = request.session.get('username', None)
    if username is not None:
        storage = Storage(CredentialModel, 'user', username, 'credential')
        storage.delete()
        request.session['username'] = None
    return HttpResponseRedirect('/')
