
import os
from functools import wraps

from oauth2client.django_orm import Storage

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse

from mysite import settings

from gloebitexample.models import CredentialModel

import gloebit

CLIENT_SECRETS = os.path.join(os.path.dirname(__file__),
                              '..',
                              'client_secrets.json')

MERCHANT = gloebit.Merchant(gloebit.Client_Secrets.from_file(CLIENT_SECRETS),
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
    }
    return render(request, 'GloebitEx/index.html', context)

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
        storage.put(None)
        request.session['username'] = None
    return HttpResponseRedirect('/')