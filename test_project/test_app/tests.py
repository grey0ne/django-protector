from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test.utils import override_settings
from test_app.models import TestPost
from protector.models import GenericGlobalPerm

TestUser = get_user_model()


@override_settings(
    DISABLE_GENERIC_PERMISSION_CACHE=True
)
class AutoMemberTest(TestCase):

    def setUp(self):
        self.test_user = TestUser.objects.create(
            username='test1', email='test@test.com'
        )
        self.test_user2 = TestUser.objects.create(
            username='test2', email='test2@test.com'
        )
        self.test_user3 = TestUser.objects.create(
            username='test3', email='test3@test.com'
        )
        self.post = TestPost.objects.create(
            author=self.test_user
        )
        self.manage_post_perm = Permission.objects.get(
            content_type__app_label='test_app',
            codename='manage_post'
        )
        GenericGlobalPerm.objects.create(
            permission=self.manage_post_perm,
            roles=TestPost.AUTHOR,
            content_type=ContentType.objects.get_for_model(TestPost)
        )

    def test_auto_member_on_create(self):
        self.assertTrue(
            self.test_user.has_perm('test_app.manage_post', self.post)
        )

    def test_auto_member_on_update(self):
        self.assertFalse(
            self.test_user2.has_perm('test_app.manage_post', self.post)
        )
        TestPost.objects.filter(id=self.post.id).update(author=self.test_user2) 
        self.assertTrue(
            self.test_user2.has_perm('test_app.manage_post', self.post)
        )

    def test_auto_member_on_save(self):
        self.assertFalse(
            self.test_user3.has_perm('test_app.manage_post', self.post)
        )
        self.post.author = self.test_user3
        self.post.save()
        self.assertTrue(
            self.test_user3.has_perm('test_app.manage_post', self.post)
        )
