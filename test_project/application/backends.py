from protector.backends import GenericPermissionBackend
from django.contrib.auth.backends import ModelBackend


class TestBackend(GenericPermissionBackend, ModelBackend):
    pass
