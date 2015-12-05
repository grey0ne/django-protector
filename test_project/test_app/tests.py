from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from test_app.models import TestPost
from protector.models import GenericGlobalPerm

TestUser = get_user_model()


class AutoMemberTest(TestCase):

    def setUp(self):
        self.test_user = TestUser.objects.create(
            username='test1', email='test@test.com'
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

    def test_auto_member(self):
        self.assertTrue(
            self.test_user.has_perm('test_app.manage_post', self.post)
        )
