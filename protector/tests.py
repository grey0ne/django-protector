from django.test import TestCase
from django.contrib.auth.models import Permission
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test.utils import override_settings
from protector.models import GenericGlobalPerm, OwnerToPermission, GenericUserToGroup
from protector.internals import get_default_group_ctype, get_user_ctype
from protector.helpers import get_all_permission_owners, get_permission_owners_of_type_for_object, \
    filter_object_id_list


TestUser = get_user_model()


@override_settings(
    DISABLE_GENERIC_PERMISSION_CACHE=True
)
class GenericObjectRestrictionTest(TestCase):

    def setUp(self):
        self.TestGroup = get_default_group_ctype().model_class()
        self.user = TestUser.objects.create(username='test1', email='test@test.com')
        self.user2 = TestUser.objects.create(username='test2', email='test2@test.com')
        self.user3 = TestUser.objects.create(username='test3', email='test3@test.com')
        self.permission = Permission.objects.create(
            codename='test', content_type=get_user_ctype()
        )
        self.permission2 = Permission.objects.create(
            codename='test2', content_type=get_user_ctype()
        )
        self.permission_key = get_user_ctype().app_label + '.test'
        self.permission2_key = get_user_ctype().app_label + '.test2'
        self.group = self.TestGroup.objects.create(
            name='test_group'
        )
        self.group2 = self.TestGroup.objects.create(
            name='test_group2'
        )
        self.group2.restrict()
        self.group2.save()

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
        self.user2.groups.add(self.group)
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
        self.assertFalse(
            self.user2.has_perm(self.permission2_key, self.group)
        )
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
        self.user2.is_superuser = True
        self.user2.save()
        self.user.permissions.add(self.permission)
        self.assertEquals(
            get_all_permission_owners(self.permission).count(), 1
        )
        self.group.permissions.add(self.permission)
        self.group.users.add(self.user2)
        self.assertEquals(
            get_all_permission_owners(self.permission).count(), 2
        )
        self.assertEquals(
            get_all_permission_owners(
                self.permission2, include_superuser=True
            ).count(), 1
        )

    def test_unrestrict(self):
        self.group.restrict()
        self.assertEquals(
            self.TestGroup.objects.visible(self.user2).count(), 0
        )
        self.group.unrestrict()
        self.assertEquals(
            self.TestGroup.objects.visible(self.user2).count(), 1
        )

    def test_ctype_owners(self):
        owners = get_permission_owners_of_type_for_object(
            permission=self.TestGroup.get_view_permission(),
            owner_content_type=ContentType.objects.get_for_model(TestUser),
            content_object=self.group2
        )
        self.assertEquals(
            owners.count(), 0
        )
        self.group2.add_viewer(self.user2)
        self.assertEquals(
            owners.count(), 1
        )

    def test_ctype_permission(self):
        groups = self.TestGroup.objects.visible(self.user2)
        self.assertFalse(
            self.user2.has_perm(self.TestGroup.VIEW_PERMISSION_NAME, self.group2)
        )
        self.assertEquals(
            groups.count(), 1
        )
        OwnerToPermission.objects.create(
            owner=self.user2,
            content_type=ContentType.objects.get_for_model(self.TestGroup),
            permission=self.TestGroup.get_view_permission(),
        )
        self.assertEquals(
            groups.count(), 2
        )
        self.assertTrue(
            self.user2.has_perm(self.TestGroup.VIEW_PERMISSION_NAME, self.group2)
        )

    def test_superuser(self):
        groups = self.TestGroup.objects.visible(self.user2)
        self.assertFalse(
            self.user2.has_perm(self.TestGroup.VIEW_PERMISSION_NAME, self.group2)
        )
        self.assertEquals(
            groups.count(), 1
        )
        self.user2.is_superuser = True
        groups = self.TestGroup.objects.visible(self.user2)
        self.assertEquals(
            groups.count(), 2
        )
        self.assertTrue(
            self.user2.has_perm(self.TestGroup.VIEW_PERMISSION_NAME, self.group2)
        )

    def test_groups_by_ctype(self):
        DEFAULT = 1
        ROLE2 = 2
        self.group2.users.add(self.user2, roles=DEFAULT)
        self.assertEquals(
            self.user2.groups.by_ctype(
                ContentType.objects.get_for_model(self.group2), DEFAULT
            ).count(), 1
        )
        self.assertEquals(
            self.user2.groups.by_ctype(
                ContentType.objects.get_for_model(self.group2), ROLE2
            ).count(), 0
        )

    def test_user_to_group_by_role(self):
        utg_qset = GenericUserToGroup.objects.filter(
            group_id=self.group2.pk,
            group_content_type=ContentType.objects.get_for_model(self.group2),
            user=self.user2
        )
        DEFAULT = 1
        ROLE2 = 2
        ROLE3 = 4
        self.group2.users.add(self.user2, roles=ROLE2)
        self.assertEquals(
            utg_qset.by_role(DEFAULT).count(), 0
        )
        self.assertEquals(
            utg_qset.by_role(ROLE2).count(), 1
        )
        self.group2.users.add(self.user2, roles=ROLE3)
        self.assertEquals(
            utg_qset.by_role(ROLE2).count(), 1
        )
        self.user2.groups.remove(self.group2, ROLE2)
        self.assertEquals(
            utg_qset.by_role(ROLE2).count(), 0
        )
        self.assertEquals(
            utg_qset.by_role(ROLE3).count(), 1
        )
        self.user2.groups.remove(self.group2, ROLE3)
        self.user2.groups.remove(self.group2, ROLE3)  # Test DoesNotExist
        self.assertEquals(
            utg_qset.by_role(ROLE3).count(), 0
        )

    def test_permissioned_manager(self):
        groups = self.TestGroup.by_perm.filter_by_permission(
            self.user2, self.TestGroup.VIEW_PERMISSION_NAME
        )
        self.assertEquals(
            groups.count(), 0
        )
        self.user2.permissions.add(self.group2.get_view_permission(), self.group2)
        self.assertEquals(
            groups.count(), 1
        )

    def test_otp_unicode(self):
        OwnerToPermission.objects.create(
            owner=self.user2,
            content_type=ContentType.objects.get_for_model(self.TestGroup),
            permission=self.TestGroup.get_view_permission(),
        )
        otps = [otp.__unicode__() for otp in OwnerToPermission.objects.all()]
        self.assertEquals(
            otps[0], u'test_app.testuser.2 Roles 1. Permission view_restricted_objects'
        )

    def test_has_perms(self):
        self.user2.permissions.add(self.permission)
        self.assertFalse(
            self.user2.has_perms([self.permission_key, self.permission2_key])
        )
        self.user2.permissions.add(self.permission2)
        self.assertTrue(
            self.user2.has_perms([self.permission_key, self.permission2_key])
        )

    def test_has_module_perms(self):
        app_label = get_user_model()._meta.app_label
        self.assertFalse(
            self.user2.has_module_perms(app_label)
        )
        self.user2.permissions.add(self.permission)
        self.assertTrue(
            self.user2.has_module_perms(app_label)
        )

    def test_object_list_filter(self):
        group_ctype = ContentType.objects.get_for_model(self.TestGroup)
        obj_list = (
            (group_ctype.id, self.group.id),
            (group_ctype.id, self.group2.id)
        )
        self.assertEquals(
            len(filter_object_id_list(
                obj_list, self.user2.id, self.TestGroup.get_view_permission().id
            )), 0
        )
        self.user2.permissions.add(
            self.TestGroup.get_view_permission(), self.group2
        )
        self.assertEquals(
            filter_object_id_list(
                obj_list, self.user2.id, self.TestGroup.get_view_permission().id
            ), [(group_ctype.id, self.group2.id)]
        )
