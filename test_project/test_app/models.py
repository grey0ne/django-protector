from django.db import models
from django.conf import settings
from protector.models import AbstractGenericGroup, Restricted, UserGenericPermsMixin
from django.contrib.auth.models import AbstractBaseUser


class TestGroup(AbstractGenericGroup, Restricted):
    name = models.CharField(max_length=100)
    
    class Meta:
        verbose_name = u'Test Group'

class TestUser(UserGenericPermsMixin, AbstractBaseUser):
    USERNAME_FIELD = 'username'
    username = models.CharField(max_length=30, unique=True)
    email = models.CharField(max_length=50)
