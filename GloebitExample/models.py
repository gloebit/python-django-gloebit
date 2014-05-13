from django.db import models
from django.contrib.auth.models import User

from oauth2client.django_orm import CredentialsField

# Create your models here.

class CredentialModel(models.Model):
    user = models.CharField(max_length=200)
    credential = CredentialsField()
