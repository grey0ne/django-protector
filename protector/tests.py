from django.test import TestCase
from django.contrib.auth.models import Permission
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test.utils import override_settings
from protector.models import get_user_ctype, GenericGlobalPerm, get_default_group_ctype
from protector.helpers import get_all_permission_owners


TestUser = get_user_model()


@override_settings(
    AUTHENTICATION_BACKENDS=('protector.backends.GenericPermissionBackend',),
    DISABLE_GENERIC_PERMISSION_CACHE=True
)
class GenericObjectRestrictionTest(TestCase):

    def setUp(cls):
        cls.TestGroup = get_default_group_ctype().model_class()
        cls.user = TestUser.objects.create(username='test1', email='test@test.com')
        cls.user2 = TestUser.objects.create(username='test2', email='test2@test.com')
        cls.user3 = TestUser.objects.create(username='test3', email='test3@test.com')
        cls.permission = Permission.objects.create(
            codename='test', content_type=get_user_ctype()
        )
        cls.permission2 = Permission.objects.create(
            codename='test2', content_type=get_user_ctype()
        )
        cls.permission_key = get_user_ctype().app_label + '.test'
        cls.permission2_key = get_user_ctype().app_label + '.test2'
        cls.group = cls.TestGroup.objects.create(
            name='test_group'
        )
        cls.group2 = cls.TestGroup.objects.create(
            name='test_group2'
        )
        cls.group2.restrict()
        cls.group2.save()

    def test_object_perm(self):
        self.assertFalse(
            self.user.has_perm(self.permission_key, self.user2)
        )
        self.user.permissions.add(
            self.permission, self.user2
        )
        self.assertTrue(
            self.user.has_perm(self.permission_key, self.user2)
        )

    def test_object_global_perm(self):
        self.assertFalse(
            self.user.has_perm(self.permission_key, self.user2)
        )
        self.user.permissions.add(self.permission)
        self.assertTrue(
            self.user.has_perm(self.permission_key, self.user2)
        )

    def test_object_group_perm_add_remove(self):
        self.assertFalse(
            self.user2.has_perm(self.permission_key, self.user)
        )
        self.group.permissions.add(self.permission, self.user)
        self.group.users.add(self.user2)
        self.assertTrue(
            self.user2.has_perm(self.permission_key, self.user)
        )
        self.group.permissions.remove(self.permission, self.user)
        self.assertFalse(
            self.user2.has_perm(self.permission_key, self.user)
        )

    def test_group_perm(self):
        self.group.users.add(self.user2)
        self.group.permissions.add(self.permission)
        self.group.permissions.add(self.permission2)
        self.assertTrue(
            self.user2.has_perm(self.permission_key)
        )
        self.group.permissions.remove(self.permission)
        self.assertFalse(
            self.user2.has_perm(self.permission_key)
        )
        self.assertTrue(
            self.user2.has_perm(self.permission2_key)
        )
        self.group.users.remove(self.user2)
        self.assertFalse(
            self.user2.has_perm(self.permission2_key)
        )

    def test_restricted_query_set(self):
        self.assertEquals(
            self.TestGroup.objects.count(), 2
        )
        self.assertEquals(
            self.TestGroup.objects.visible().count(), 1
        )
        self.assertEquals(
            self.TestGroup.objects.visible(self.user).count(), 1
        )
        self.user.permissions.add(
            self.TestGroup.get_view_permission()
        )
        self.assertEquals(
            self.TestGroup.objects.visible(self.user).count(), 2
        )

    def test_restricted_query_set_object_permission(self):
        self.assertEquals(
            self.TestGroup.objects.visible(self.user2).count(), 1
        )
        self.user2.permissions.add(
            self.TestGroup.get_view_permission(), self.group2
        )
        qset = self.TestGroup.objects.visible(self.user2)
        self.assertEquals(qset.count(), 2)
        self.assertEquals(qset.filter(name=self.group2.name).count(), 1)

    def test_user_roles(self):
        DEFAULT = 1
        ROLE2 = 2
        ROLE3 = 4
        self.assertEquals(
            self.group.users.count(), 0
        )
        self.group.users.add(self.user)
        self.assertEquals(
            self.group.users.count(), 1
        )
        self.group.users.add(self.user2, roles=DEFAULT+ROLE2)

        self.assertEquals(
            self.group.users.by_role(roles=DEFAULT).count(), 2
        )
        self.assertEquals(
            self.group.users.by_role(roles=ROLE2).count(), 1
        )
        self.assertEquals(
            self.group.users.by_role(roles=ROLE3).count(), 0
        )
        self.group.users.add(self.user3, roles=ROLE3)
        self.assertEquals(
            self.group.users.by_role(roles=ROLE2+ROLE3).count(), 2
        )

    def test_content_type_perm(self):
        DEFAULT = 1
        ROLE2 = 2
        self.group.users.add(self.user2, roles=ROLE2)
        self.group.users.add(self.user, roles=DEFAULT)
        GenericGlobalPerm.objects.create(
            content_type=ContentType.objects.get_for_model(self.TestGroup),
            roles=ROLE2, permission=self.permission2
        )
        self.assertTrue(
            self.user2.has_perm(self.permission2_key, self.group)
        )
        self.assertFalse(
            self.user2.has_perm(self.permission2_key, self.group2)
        )
        self.assertFalse(
            self.user.has_perm(self.permission2_key, self.group)
        )

    def test_qset_ctype_perm(self):
        ROLE2 = 2
        self.assertEquals(
            self.TestGroup.objects.visible(self.user2).count(), 1
        )
        GenericGlobalPerm.objects.create(
            content_type=ContentType.objects.get_for_model(self.TestGroup),
            roles=ROLE2, permission=self.TestGroup.get_view_permission()
        )
        self.group.users.add(self.user)
        self.group2.users.add(self.user2, roles=ROLE2)
        self.assertEquals(
            self.TestGroup.objects.visible(self.user2).count(), 2
        )
        self.assertEquals(
            self.TestGroup.objects.visible(self.user).count(), 1
        )

    def test_all_permission_owners(self):
        self.user.permissions.add(self.permission)
        self.assertEquals(
            get_all_permission_owners(self.permission).count(), 1
        )
        self.group.permissions.add(self.permission)
        self.group.users.add(self.user2)
        self.assertEquals(
            get_all_permission_owners(self.permission).count(), 2
        )
