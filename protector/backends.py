from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from protector.helpers import get_all_user_permissions, check_single_permission


ALL_PERMS_CACHE_FIELD = '_all_permissions_cache'
ALL_PERMS_CACHE_DICT_FIELD = '_all_permissions_cache'


def generate_perm_list(perm_qset):
    perm_qset = perm_qset.values_list('content_type__app_label', 'codename')
    return set("{0}.{1}".format(ct, name) for ct, name in perm_qset)


def get_cache_field_name(obj=None):
    if obj is None:
        cache_field_name = ALL_PERMS_CACHE_FIELD
    else:
        cache_field_name = '{field}_{pk}_{ctype_id}'.format(
            field=ALL_PERMS_CACHE_FIELD, pk=obj.pk,
            ctype_id=ContentType.objects.get_for_model(obj).id
        )
    return cache_field_name


class GenericPermissionBackend(object):
    def authenticate(self, request, username=None, password=None):
        return None

    def get_all_permissions(self, user_obj, obj=None):
        if not user_obj.is_active or user_obj.is_anonymous:
            return set()
        disable_cache = getattr(settings, 'DISABLE_GENERIC_PERMISSION_CACHE', False)
        if user_obj.is_superuser:
            perms = getattr(self, '_all_permissions', None)
            if perms is None:
                perms = generate_perm_list(Permission.objects.all())
                if not disable_cache:
                    setattr(self, '_all_permissions', perms)
            return perms
        cache_field_name = get_cache_field_name(obj)
        # need this for testing purposes, do not enable this in production
        if not hasattr(user_obj, cache_field_name) or disable_cache:
            perms = get_all_user_permissions(user_obj, obj)
            setattr(user_obj, cache_field_name, perms)
        return getattr(user_obj, cache_field_name)

    def has_perm(self, user_obj, perm, obj=None):
        if not user_obj.is_active or user_obj.is_anonymous:
            return False
        disable_cache = getattr(settings, 'DISABLE_GENERIC_PERMISSION_CACHE', False)
        cache_field_name = get_cache_field_name(obj) + '_dict'
        if not hasattr(user_obj, cache_field_name) or disable_cache:
            setattr(user_obj, cache_field_name, {})
        perm_dict = getattr(user_obj, cache_field_name)
        if perm not in perm_dict or disable_cache:
            check_result = check_single_permission(user_obj, perm, obj)
            perm_dict[perm] = check_result
        return perm_dict[perm]

    def has_module_perms(self, user_obj, app_label):
        if not user_obj.is_active:
            return False
        for perm in self.get_all_permissions(user_obj):
            if perm[:perm.index('.')] == app_label:
                return True
        return False

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel._default_manager.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
