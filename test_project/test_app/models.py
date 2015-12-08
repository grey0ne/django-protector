from django.db import models
from protector.models import AbstractGenericGroup, Restricted, UserGenericPermsMixin
from protector.querysets import GenericGroupQuerySet, RestrictedQuerySet
from protector.managers import PermissionedManager
from django.contrib.auth.models import AbstractBaseUser, UserManager


class RestrictedGroupQuerySet(GenericGroupQuerySet, RestrictedQuerySet):
    pass

RestrictedGroupManager = models.Manager.from_queryset(RestrictedGroupQuerySet)


class TestGroup(AbstractGenericGroup, Restricted):
    name = models.CharField(max_length=100)

    objects = RestrictedGroupManager()

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


class TestPost(AbstractGenericGroup):
    SUBSCRIBER = 1
    AUTHOR = 2
    ROLES = (
        (SUBSCRIBER, 'Subscriber'),
        (AUTHOR, 'Author')
    )
    author = models.ForeignKey(to=TestUser)

    MEMBER_FOREIGN_KEY_FIELDS = (
        ('author', AUTHOR),
    )

    class Meta:
        permissions = (
            ('manage_post', 'Manage Post'),
        )
