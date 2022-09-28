try:
    from unittest import mock
except ImportError:
    import mock
from django.test import TestCase
from django.db import IntegrityError
from django.contrib.auth.models import Permission
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test.utils import override_settings

from protector.backends import BaseGenericPermissionBackend
from protector.exceptions import NoReasonSpecified, ImproperResponsibleInstancePassed
from protector.models import (
    GenericGlobalPerm,
    OwnerToPermission,
    HistoryOwnerToPermission,
    GenericUserToGroup,
    HistoryGenericUserToGroup,
)
from protector.reserved_reasons import TEST_REASON
from protector.internals import get_default_group_ctype, get_user_ctype
from protector.helpers import (
    get_all_permission_owners, get_permission_owners_of_type_for_object,
    filter_object_id_list, is_user_having_perm_on_any_object, check_single_permission
)


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
        self.responsible_user = TestUser.objects.create_user(username='responsible')
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
        self.HistoryOwnerToPermission = HistoryOwnerToPermission
        self.HistoryGenericUserToGroup = HistoryGenericUserToGroup

    def test_object_perm(self):
        self.assertFalse(
            self.user.has_perm(self.permission_key, self.user2)
        )
        self.user.permissions.add(
            self.permission,
            TEST_REASON,
            obj=self.user2,
            responsible=self.responsible_user,
        )
        self.assertTrue(
            self.user.has_perm(self.permission_key, self.user2)
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 1)

    def test_object_global_perm(self):
        self.assertFalse(
            self.user.has_perm(self.permission_key, self.user2)
        )
        self.user.permissions.add(
            self.permission,
            TEST_REASON,
            responsible=self.responsible_user,
        )
        self.assertTrue(
            self.user.has_perm(self.permission_key, self.user2)
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 1)

    def test_object_group_perm_add_remove(self):
        self.assertFalse(
            self.user2.has_perm(self.permission_key, self.user)
        )
        self.group.permissions.add(
            self.permission,
            TEST_REASON,
            obj=self.user,
            responsible=self.responsible_user,
        )
        self.group.users.add(
            self.user2,
            TEST_REASON,
            responsible=self.responsible_user,
        )
        self.assertTrue(
            self.user2.has_perm(self.permission_key, self.user)
        )
        self.group.permissions.remove(
            self.permission,
            TEST_REASON,
            obj=self.user,
            responsible=self.responsible_user,
        )
        self.assertFalse(
            self.user2.has_perm(self.permission_key, self.user)
        )
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 1)
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 2)

    def test_group_perm(self):
        self.user2.groups.add(self.group, TEST_REASON, responsible=self.responsible_user)
        self.group.permissions.add(self.permission, TEST_REASON, responsible=self.responsible_user)
        self.group.permissions.add(self.permission2, TEST_REASON, responsible=self.responsible_user)
        self.assertTrue(
            self.user2.has_perm(self.permission_key)
        )
        self.group.permissions.remove(self.permission, TEST_REASON, responsible=self.responsible_user)
        self.assertFalse(
            self.user2.has_perm(self.permission_key)
        )
        self.assertTrue(
            self.user2.has_perm(self.permission2_key)
        )
        self.group.users.remove(self.user2, TEST_REASON, responsible=self.responsible_user)
        self.assertFalse(
            self.user2.has_perm(self.permission2_key)
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 3)
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 2)

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
            self.TestGroup.get_view_permission(),
            TEST_REASON, responsible=self.responsible_user
        )
        self.assertEquals(
            self.TestGroup.objects.visible(self.user).count(), 2
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

    def test_restricted_query_set_object_permission(self):
        self.assertEquals(
            self.TestGroup.objects.visible(self.user2).count(), 1
        )
        self.user2.permissions.add(
            self.TestGroup.get_view_permission(),
            TEST_REASON, responsible=self.responsible_user,
            obj=self.group2
        )
        qset = self.TestGroup.objects.visible(self.user2)
        self.assertEquals(qset.count(), 2)
        self.assertEquals(qset.filter(name=self.group2.name).count(), 1)
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

    def test_user_roles(self):
        DEFAULT = 1
        ROLE2 = 2
        ROLE3 = 4
        self.assertEquals(
            self.group.users.count(), 0
        )
        self.group.users.add(self.user, TEST_REASON, responsible=self.responsible_user)
        self.assertEquals(
            self.group.users.count(), 1
        )
        self.group.users.add(self.user2, TEST_REASON, roles=DEFAULT+ROLE2, responsible=self.responsible_user)

        self.assertEquals(
            self.group.users.by_role(roles=DEFAULT).count(), 2
        )
        self.assertEquals(
            self.group.users.by_role(roles=ROLE2).count(), 1
        )
        self.assertEquals(
            self.group.users.by_role(roles=ROLE3).count(), 0
        )
        self.group.users.add(self.user3, TEST_REASON, responsible=self.responsible_user, roles=ROLE3)
        self.assertEquals(
            self.group.users.by_role(roles=ROLE2+ROLE3).count(), 2
        )
        self.assertEquals(
            self.group.get_roles(self.user3), [ROLE3]
        )
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 3)

    def test_content_type_perm(self):
        DEFAULT = 1
        ROLE2 = 2
        self.group.users.add(self.user2, TEST_REASON, responsible=self.responsible_user, roles=ROLE2)
        self.group.users.add(self.user, TEST_REASON, responsible=self.responsible_user, roles=DEFAULT)
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
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 2)

    def test_qset_ctype_perm(self):
        ROLE2 = 2
        self.assertEquals(
            self.TestGroup.objects.visible(self.user2).count(), 1
        )
        GenericGlobalPerm.objects.create(
            content_type=ContentType.objects.get_for_model(self.TestGroup),
            roles=ROLE2, permission=self.TestGroup.get_view_permission()
        )
        self.group.users.add(self.user, TEST_REASON, responsible=self.responsible_user)
        self.group2.users.add(self.user2, TEST_REASON, responsible=self.responsible_user, roles=ROLE2)
        self.assertEquals(
            self.TestGroup.objects.visible(self.user2).count(), 2
        )
        self.assertEquals(
            self.TestGroup.objects.visible(self.user).count(), 1
        )
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 2)

    def test_all_permission_owners(self):
        self.user2.is_superuser = True
        self.user2.save()
        self.user.permissions.add(self.permission, TEST_REASON, responsible=self.responsible_user)
        self.assertEquals(
            get_all_permission_owners(self.permission).count(), 1
        )
        self.group.permissions.add(self.permission, TEST_REASON, responsible=self.responsible_user)
        self.group.users.add(self.user2, TEST_REASON, responsible=self.responsible_user)
        self.assertEquals(
            get_all_permission_owners(self.permission).count(), 2
        )
        self.assertEquals(
            get_all_permission_owners(
                self.permission2, include_superuser=True
            ).count(), 1
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 2)
        # as we create generic group to user himself
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 2)

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
        self.group2.add_viewer(self.user2, TEST_REASON, responsible=self.responsible_user)
        self.assertEquals(
            owners.count(), 1
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

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
        self.group2.users.add(self.user2, TEST_REASON, responsible=self.responsible_user, roles=DEFAULT)
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
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 1)

    def test_user_to_group_by_role(self):
        utg_qset = GenericUserToGroup.objects.filter(
            group_id=self.group2.pk,
            group_content_type=ContentType.objects.get_for_model(self.group2),
            user=self.user2
        )
        DEFAULT = 1
        ROLE2 = 2
        ROLE3 = 4
        self.group2.users.add(self.user2, TEST_REASON, responsible=self.responsible_user, roles=ROLE2)
        self.assertEquals(
            utg_qset.by_role(DEFAULT).count(), 0
        )
        self.assertEquals(
            utg_qset.by_role(ROLE2).count(), 1
        )
        self.group2.users.add(self.user2, TEST_REASON, responsible=self.responsible_user, roles=ROLE3)
        # update history record
        self.assertEquals(
            utg_qset.by_role(ROLE2).count(), 1
        )
        self.user2.groups.remove(self.group2, TEST_REASON, responsible=self.responsible_user, roles=ROLE2)
        # update history record
        self.assertEquals(
            utg_qset.by_role(ROLE2).count(), 0
        )
        self.assertEquals(
            utg_qset.by_role(ROLE3).count(), 1
        )
        self.user2.groups.remove(self.group2, TEST_REASON, ROLE3, responsible=self.responsible_user)
        self.user2.groups.remove(self.group2, TEST_REASON, ROLE3, responsible=self.responsible_user) # Test DoesNotExist
        self.assertEquals(
            utg_qset.by_role(ROLE3).count(), 0
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 0)
        all_hist_records = self.HistoryGenericUserToGroup.objects.all()
        self.assertEqual(
            all_hist_records.filter(change_type=self.HistoryGenericUserToGroup.TYPE_CHANGE).count(), 2
        )
        self.assertEqual(
            all_hist_records.filter(change_type=self.HistoryGenericUserToGroup.TYPE_ADD).count(), 1
        )
        self.assertEqual(
            all_hist_records.filter(change_type=self.HistoryGenericUserToGroup.TYPE_REMOVE).count(), 1
        )

    def test_permissioned_manager(self):
        groups = self.TestGroup.by_perm.filter_by_permission(
            self.user2, self.TestGroup.VIEW_PERMISSION_NAME
        )
        self.assertEquals(
            groups.count(), 0
        )
        self.user2.permissions.add(
            self.group2.get_view_permission(),
            TEST_REASON,
            self.group2,
            responsible=self.responsible_user
        )
        self.assertEquals(
            groups.count(), 1
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

    def test_otp_unicode(self):
        OwnerToPermission.objects.create(
            owner=self.user2,
            reason=TEST_REASON,
            content_type=ContentType.objects.get_for_model(self.TestGroup),
            permission=self.TestGroup.get_view_permission(),
        )
        otps = [otp.__unicode__() for otp in OwnerToPermission.objects.all()]
        self.assertEquals(
            otps[0], u'test_app.testuser.2 Roles 1. Permission view_restricted_objects'
        )

    def test_has_perms(self):
        self.user2.permissions.add(self.permission, TEST_REASON)
        self.assertFalse(
            self.user2.has_perms([self.permission_key, self.permission2_key])
        )
        self.user2.permissions.add(self.permission2, TEST_REASON)
        self.assertTrue(
            self.user2.has_perms([self.permission_key, self.permission2_key])
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 2)

    def test_has_module_perms(self):
        app_label = get_user_model()._meta.app_label
        self.assertFalse(
            self.user2.has_module_perms(app_label)
        )
        self.user2.permissions.add(self.permission, TEST_REASON)
        self.assertTrue(
            self.user2.has_module_perms(app_label)
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

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
            self.TestGroup.get_view_permission(), TEST_REASON, self.group2, responsible=self.responsible_user
        )
        self.assertEquals(
            filter_object_id_list(
                obj_list, self.user2.id, self.TestGroup.get_view_permission().id
            ), [(group_ctype.id, self.group2.id)]
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

    def test_user_has_perm_on_any_object(self):
        self.assertFalse(
            is_user_having_perm_on_any_object(self.user, self.permission_key)
        )
        self.user.permissions.add(self.permission, TEST_REASON, self.group2, responsible=self.responsible_user)
        self.assertTrue(
            is_user_having_perm_on_any_object(self.user, self.permission_key)
        )
        self.assertFalse(
            is_user_having_perm_on_any_object(self.user, self.permission2_key)
        )
        self.user.permissions.add(self.permission, TEST_REASON, self.group2)
        self.user.permissions.remove(self.permission, TEST_REASON, self.group2)
        self.assertFalse(
            is_user_having_perm_on_any_object(self.user, self.permission_key)
        )
        self.user.permissions.add(self.permission, TEST_REASON, responsible=self.responsible_user)
        self.assertTrue(
            is_user_having_perm_on_any_object(self.user, self.permission_key)
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 3)

    def test_superuser_has_perm_on_any_object(self):
        self.assertFalse(
            is_user_having_perm_on_any_object(self.user, self.permission_key)
        )
        self.user.is_superuser = True
        self.user.save()
        self.assertTrue(
            is_user_having_perm_on_any_object(self.user, self.permission_key)
        )

    def test_single_permission_helper_global(self):
        self.assertFalse(
            check_single_permission(self.user, self.permission_key, self.group)
        )
        self.user.permissions.add(self.permission, TEST_REASON, responsible=self.responsible_user)
        self.assertTrue(
            check_single_permission(self.user, self.permission_key, self.group)
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

    def test_single_permission_helper_on_object(self):
        self.assertFalse(
            check_single_permission(self.user, self.permission_key, self.group)
        )
        self.user.permissions.add(self.permission, TEST_REASON, obj=self.group, responsible=self.responsible_user)
        self.assertTrue(
            check_single_permission(self.user, self.permission_key, self.group)
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

    def test_single_permission_global(self):
        self.assertFalse(
            check_single_permission(self.user, self.permission_key)
        )
        self.user.permissions.add(self.permission, TEST_REASON, obj=self.group)
        self.assertFalse(
            check_single_permission(self.user, self.permission_key)
        )
        self.user.permissions.add(self.permission, TEST_REASON)
        self.assertTrue(
            check_single_permission(self.user, self.permission_key)
        )
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 2)

    def test_non_existing_permission(self):
        self.assertFalse(
            check_single_permission(self.user, 'not.exist', self.group)
        )
        self.assertFalse(
            check_single_permission(self.user, 'not.exist')
        )

    def test_no_owner_duplicates_allowed(self):
        create_test_dict = {
            'owner': self.user,
            'permission': self.permission,
            'reason': TEST_REASON,
        }
        try:
            # Intentionally forgetting to point reason
            OwnerToPermission.objects.create(owner=self.user, permission=self.permission)
        except NoReasonSpecified:
            pass
        OwnerToPermission.objects.create(**create_test_dict)
        try:
            # Intentionally creating the same record
            OwnerToPermission.objects.create(**create_test_dict)
        except IntegrityError:
            pass

        _, created = OwnerToPermission.objects.get_or_create(
            owner_content_type=ContentType.objects.get_for_model(self.user),
            owner_object_id=self.user.id,
            permission=self.permission,
            reason=TEST_REASON
        )
        self.assertEqual(created, False)
        self.assertEqual(OwnerToPermission.objects.count(), 1)
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 1)

        _, created = OwnerToPermission.objects.get_or_create(
            owner_content_type=ContentType.objects.get_for_model(self.user),
            owner_object_id=self.user.id,
            permission=self.permission2,
            reason=TEST_REASON
        )

        self.assertEqual(created, True)
        self.assertEqual(OwnerToPermission.objects.count(), 2)
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 2)

    def test_otp_redefined_manager_methods(self):
        otp = OwnerToPermission.objects.create(permission=self.permission, owner=self.user, reason=TEST_REASON)
        self.assertEqual(
            self.HistoryOwnerToPermission.objects.filter(change_type=self.HistoryOwnerToPermission.TYPE_ADD).count(),
            self.HistoryOwnerToPermission.objects.count()
        )

        # model delete method
        self.assertRaises(NoReasonSpecified, otp.delete)
        delete_result = otp.delete(reason=TEST_REASON)
        self.assertTrue(isinstance(delete_result, tuple))
        self.assertEqual(delete_result[0], 1)
        self.assertEqual(
            self.HistoryOwnerToPermission.objects.filter(change_type=self.HistoryOwnerToPermission.TYPE_ADD).count(),
            self.HistoryOwnerToPermission.objects.filter(change_type=self.HistoryOwnerToPermission.TYPE_REMOVE).count(),
        )

        self_role = 1

        # model save method
        otp = OwnerToPermission(permission=self.permission, owner=self.user, content_object=self.group)
        self.assertRaises(NoReasonSpecified, otp.save)
        otp.save(reason=TEST_REASON)
        self.assertEqual(
            self.HistoryOwnerToPermission.objects.filter(change_type=self.HistoryOwnerToPermission.TYPE_ADD).count(), 2
        )
        # user is a part of group of his own
        self.assertTrue(self.user in self.user.users.all())
        self.assertCountEqual(self.user.get_roles(self.user), [self_role])
        # role change
        self.assertEqual(
            self.HistoryOwnerToPermission.objects.filter(change_type=self.HistoryOwnerToPermission.TYPE_CHANGE).count(),
            0
        )
        otp.roles = 2
        otp.save(reason=TEST_REASON)
        self.assertEqual(
            self.HistoryOwnerToPermission.objects.filter(change_type=self.HistoryOwnerToPermission.TYPE_CHANGE).count(),
            1
        )

        # manager delete method
        self.assertRaises(NoReasonSpecified, OwnerToPermission.objects.all().delete)
        try:
            OwnerToPermission.objects.all().delete(reason=TEST_REASON, responsible=self.responsible_user)
        except ImproperResponsibleInstancePassed:
            pass
        OwnerToPermission.objects.all().delete(reason=TEST_REASON, responsible=self.responsible_user)
        self.assertEqual(self.HistoryOwnerToPermission.objects.count(), 5)
        self.assertEqual(
            self.HistoryOwnerToPermission.objects.filter(change_type=self.HistoryOwnerToPermission.TYPE_REMOVE).count(),
            2
        )

        # remove user from himself and add with other role
        self.user.users.remove(self.user, reason=TEST_REASON)
        custom_role = 2
        self.user.users.add(self.user, roles=custom_role, reason=TEST_REASON)

        # manager bulk_create method
        otps_to_create = [
            OwnerToPermission(permission=self.permission, owner=self.user, responsible=self.responsible_user),
            OwnerToPermission(permission=self.permission2, owner=self.user2, responsible=self.responsible_user),
            OwnerToPermission(permission=self.permission, owner=self.user2,
                              content_object=self.group, responsible=self.responsible_user),
        ]
        OwnerToPermission.objects.bulk_create(otps_to_create, reason=TEST_REASON)
        self.assertEqual(OwnerToPermission.objects.count(), 3)
        self.assertEqual(
            self.HistoryOwnerToPermission.objects.filter(
                change_type=self.HistoryOwnerToPermission.TYPE_ADD,
                responsible=self.responsible_user,
            ).count(), 3
        )
        # now user is a part of group of his own again and also has custom role
        self.assertTrue(self.user in self.user.users.all())
        self.assertCountEqual(self.user.get_roles(self.user), [self_role, custom_role])
        # now user2 is a part of group of his own too
        self.assertTrue(self.user2 in self.user2.users.all())
        self.assertCountEqual(self.user2.get_roles(self.user2), [self_role])

    def test_gug_redefined_manager_methods(self):
        gug = GenericUserToGroup.objects.create(group=self.group, user=self.user, reason=TEST_REASON)
        self.assertEqual(
            self.HistoryGenericUserToGroup.objects.filter(change_type=self.HistoryGenericUserToGroup.TYPE_ADD).count(),
            self.HistoryGenericUserToGroup.objects.count()
        )

        # model delete method
        self.assertRaises(NoReasonSpecified, gug.delete)
        delete_result = gug.delete(reason=TEST_REASON)
        self.assertTrue(isinstance(delete_result, tuple))
        self.assertEqual(delete_result[0], 1)
        self.assertEqual(
            self.HistoryGenericUserToGroup.objects.filter(change_type=self.HistoryGenericUserToGroup.TYPE_ADD).count(),
            self.HistoryGenericUserToGroup.objects.filter(change_type=self.HistoryGenericUserToGroup.TYPE_REMOVE).count(),
        )

        # model save method
        gug = GenericUserToGroup(group=self.group2, user=self.user2)
        self.assertRaises(NoReasonSpecified, gug.save)
        gug.save(reason=TEST_REASON)
        self.assertEqual(
            self.HistoryGenericUserToGroup.objects.filter(change_type=self.HistoryGenericUserToGroup.TYPE_ADD).count(), 2
        )
        # role change
        self.assertEqual(
            self.HistoryGenericUserToGroup.objects.filter(change_type=self.HistoryGenericUserToGroup.TYPE_CHANGE).count(), 0
        )
        gug.roles = 2
        gug.save(reason=TEST_REASON)
        self.assertEqual(
            self.HistoryGenericUserToGroup.objects.filter(change_type=self.HistoryGenericUserToGroup.TYPE_CHANGE).count(), 1
        )

        # manager delete method

        self.assertRaises(NoReasonSpecified, GenericUserToGroup.objects.all().delete)
        try:
            GenericUserToGroup.objects.all().delete(reason=TEST_REASON, responsible=self.group)
        except ImproperResponsibleInstancePassed:
            pass
        GenericUserToGroup.objects.all().delete(reason=TEST_REASON, responsible=self.responsible_user)
        self.assertEqual(self.HistoryGenericUserToGroup.objects.count(), 5)
        self.assertEqual(
            self.HistoryGenericUserToGroup.objects.filter(change_type=self.HistoryGenericUserToGroup.TYPE_REMOVE).count(), 2
        )

        # manager bulk_create
        gugs_to_create = [
            GenericUserToGroup(group=self.group2, user=self.user2, responsible=self.responsible_user),
            GenericUserToGroup(group=self.group, user=self.user, responsible=self.responsible_user),
            GenericUserToGroup(group=self.group, user=self.user2, responsible=self.responsible_user),
        ]
        GenericUserToGroup.objects.bulk_create(gugs_to_create, reason=TEST_REASON)
        self.assertEqual(GenericUserToGroup.objects.count(), 3)
        self.assertEqual(
            self.HistoryGenericUserToGroup.objects.filter(
                change_type=self.HistoryGenericUserToGroup.TYPE_ADD,
                responsible=self.responsible_user,
            ).count(), 3
        )

    def test_responsible_reason_decorator(self):
        try:
            GenericUserToGroup.objects.create(group=self.group, user=self.user, reason='')
        except NoReasonSpecified:
            pass
        try:
            OwnerToPermission.objects.get_or_create(owner=self.user, permission=self.permission, reason='', defaults={
                'responsible': self.user2,
            })
        except NoReasonSpecified:
            pass
        try:
            OwnerToPermission.objects.create(
                owner=self.user, permission=self.permission, responsible=self.group,
                reason=TEST_REASON,
            )
        except ImproperResponsibleInstancePassed:
            pass


@override_settings(
    DISABLE_GENERIC_PERMISSION_CACHE=False
)
class TestUserPermissionCache(TestCase):
    def setUp(self):
        self.user = TestUser.objects.create(username='aragorn', email='aragorn@test.com')
        permission_code_name = 'rule_gondor'
        self.permission = Permission.objects.create(
            codename=permission_code_name, content_type=get_user_ctype()
        )
        self.permission_key = '{}.{}'.format(get_user_ctype().app_label, permission_code_name)
        self.user.permissions.add(self.permission, TEST_REASON)

    @mock.patch('protector.backends.check_single_permission')
    def test_has_perm_not_called_when_all_permissions_fetched(self, check_single_permission_mock):
        backend = BaseGenericPermissionBackend()
        backend.get_all_permissions(self.user)
        self.assertTrue(backend.has_perm(self.user, self.permission_key))
        self.assertFalse(backend.has_perm(self.user, 'some_random_permission'))
        self.assertEqual(check_single_permission_mock.call_count, 0)


@override_settings(
    DISABLE_GENERIC_PERMISSION_CACHE=False
)
class TestGenericUserToGroupSelf(TestCase):
    def setUp(self):
        self.user = TestUser.objects.create(username='aragorn', email='aragorn@test.com')
        permission_code_name = 'rule_gondor'
        self.permission = Permission.objects.create(
            codename=permission_code_name, content_type=get_user_ctype()
        )

    def test_add_user_to_himself(self):
        """
        When we give user any permission, his is added to a group of his own.
        """
        self.assertFalse(GenericUserToGroup.objects.all())
        self.user.permissions.add(self.permission, TEST_REASON)
        self.assertTrue(
            GenericUserToGroup.objects.filter(
                user=self.user,
                group_id=self.user.id,
                group_content_type=get_user_ctype(),
                roles=TestUser.SELF,
            )
        )

    def test_add_user_to_himself_already_added(self):
        """
        If user was already part of a group of his own without self role, we add self role.
        """
        self.assertEqual(0, self.user.users.by_role(roles=TestUser.SELF).count())
        self.assertEqual(0, self.user.users.by_role(roles=TestUser.ASSISTANT).count())

        GenericUserToGroup.objects.create(
            user=self.user,
            group_id=self.user.id,
            group_content_type=get_user_ctype(),
            roles=TestUser.ASSISTANT,
            reason=TEST_REASON,
        )

        self.assertEqual(0, self.user.users.by_role(roles=TestUser.SELF).count())
        self.assertEqual(1, self.user.users.by_role(roles=TestUser.ASSISTANT).count())

        self.user.permissions.add(self.permission, TEST_REASON)

        self.assertEqual(1, self.user.users.by_role(roles=TestUser.SELF).count())
        self.assertEqual(1, self.user.users.by_role(roles=TestUser.ASSISTANT).count())
