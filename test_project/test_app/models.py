from django.db import models
from django.conf import settings
from protector.models import AbstractGenericGroup, Restricted, UserGenericPermsMixin,\
    PermissionedManager
from django.contrib.auth.models import AbstractBaseUser, UserManager


class TestGroup(AbstractGenericGroup, Restricted):
    name = models.CharField(max_length=100)
    
    by_perm = PermissionedManager()
    
    class Meta:
        verbose_name = u'Test Group'

class TestUser(UserGenericPermsMixin, AbstractBaseUser):
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ('email', )  
    username = models.CharField(max_length=30, unique=True)
    is_staff = models.BooleanField(
        default=False,
    )
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)

    email = models.CharField(max_length=50)

    objects = UserManager()
    
    def get_short_name(self):
        return self.username

    def get_full_name(self):
        return self.username
