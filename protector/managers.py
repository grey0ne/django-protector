from django.db import models
from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from protector.querysets import GenericUserToGroupQuerySet, PermissionQuerySet, \
    RestrictedQuerySet, OwnerToPermissionQuerySet, GenericGroupQuerySet
from protector.internals import get_default_group_ctype, DEFAULT_ROLE, \
    NULL_OWNER_TO_PERMISSION_OBJECT_ID, NULL_OWNER_TO_PERMISSION_CTYPE_ID
from protector.helpers import get_permission_id_by_name


GenericUserToGroupManager = models.Manager.from_queryset(GenericUserToGroupQuerySet)

PermissionedManager = models.Manager.from_queryset(PermissionQuerySet)

RestrictedManager = models.Manager.from_queryset(RestrictedQuerySet)

OwnerToPermissionManager = models.Manager.from_queryset(OwnerToPermissionQuerySet)

GenericGroupManager = models.Manager.from_queryset(GenericGroupQuerySet)


class UserGroupManager(models.Manager):

    def __init__(self, instance):
        super(UserGroupManager, self).__init__()
        self.instance = instance

    def add(self, *groups, **kwargs):
        roles = kwargs.get('roles')
        responsible = kwargs.get('responsible')
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        for group in groups:
            roles = roles or group.DEFAULT_ROLE
            utg, created = GenericUserToGroup.objects.get_or_create(
                user=self.instance,
                group_id=group.pk,
                group_content_type=ContentType.objects.get_for_model(group),
                defaults={'responsible': responsible, 'roles': roles}
            )
            if not created and utg.roles != roles:
                utg.roles |= roles
                utg.save()

    def remove(self, group, roles=None):
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        try:
            utg = GenericUserToGroup.objects.get(
                group_id=group.pk,
                group_content_type=ContentType.objects.get_for_model(group),
                user=self.instance
            )
        except GenericUserToGroup.DoesNotExist:
            return
        if roles is None or utg.roles == roles:
            utg.delete()
        else:
            utg.roles &= ~roles
            utg.save()

    def get_queryset(self, group_type=None):
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        if group_type is None:
            group_type = get_default_group_ctype()
        return group_type.model_class().objects.filter(
            pk__in=GenericUserToGroup.objects.filter(
                group_content_type=group_type,
                user=self.instance
            ).values_list('group_id')
        )

    def by_ctype(self, group_type, roles=None):
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        group_model = group_type.model_class()
        utg_qset = GenericUserToGroup.objects.filter(
            group_content_type=group_type,
            user=self.instance
        )
        if roles is not None:
            utg_qset = utg_qset.extra(where=["roles & %s"], params=[roles])
        return group_model.objects.filter(
            pk__in=utg_qset.values_list('group_id')
        )


class GroupUserManager(models.Manager):

    def __init__(self, instance):
        super(GroupUserManager, self).__init__()
        self.instance = instance

    def get_queryset(self):
        user_ids = self.instance.users_relations.values_list('user_id', flat=True)
        return get_user_model().objects.filter(id__in=user_ids)

    def add(self, *users, **kwargs):
        roles = kwargs.get('roles', self.instance.DEFAULT_ROLE)
        responsible = kwargs.get('responsible')
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        for user in users:
            gug, created = GenericUserToGroup.objects.get_or_create(
                user=user, group_id=self.instance.id,
                group_content_type=ContentType.objects.get_for_model(self.instance),
                defaults={'roles': roles, 'responsible': responsible}
            )
            if not created:
                gug.roles |= roles
                gug.save()

    def remove(self, user, roles=None):
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        # if roles is None just remove user from group else remove role from user
        try:
            utg = GenericUserToGroup.objects.get(
                group_id=self.instance.pk,
                group_content_type=ContentType.objects.get_for_model(self.instance),
                user=user
            )
        except GenericUserToGroup.DoesNotExist:
            return
        if roles is None or utg.roles == roles:
            utg.delete()
        else:
            utg.roles &= ~roles
            utg.save()

    def by_role(self, roles):
        links = self.instance.users_relations.all()
        if roles is None:
            links = links.filter(roles__isnull=True)
        else:
            links = links.extra(where=["roles & %s"], params=[roles])
        return get_user_model().objects.filter(id__in=links.values_list('user_id', flat=True))


class OwnerPermissionManager(models.Manager):

    def __init__(self, instance):
        super(OwnerPermissionManager, self).__init__()
        self.instance = instance

    def get_queryset(self):
        ctype = ContentType.objects.get_for_model(self.instance)
        Permission = apps.get_model('auth', 'Permission')
        return Permission.objects.filter(
            generic_restriction_relations__owner_object_id__in=[self.instance.pk],
            generic_restriction_relations__owner_content_type__in=[ctype]
        ).distinct()

    def add(self, perm, obj=None, responsible=None, roles=None):
        roles = roles or DEFAULT_ROLE
        kwargs = {
            'owner_object_id': self.instance.id,
            'owner_content_type': ContentType.objects.get_for_model(self.instance),
            'defaults': {'responsible': responsible, 'roles': roles}
        }
        if isinstance(perm, str):
            kwargs['permission_id'] = get_permission_id_by_name(perm)
        else:
            kwargs['permission'] = perm

        if obj is not None:
            kwargs['object_id'] = obj.pk
            kwargs['content_type'] = ContentType.objects.get_for_model(obj)
        else:
            kwargs['object_id'] = NULL_OWNER_TO_PERMISSION_OBJECT_ID
            kwargs['content_type'] = ContentType.objects.get_for_id(
                NULL_OWNER_TO_PERMISSION_CTYPE_ID
            )

        OwnerToPermission = apps.get_model('protector', 'OwnerToPermission')
        otp, created = OwnerToPermission.objects.get_or_create(
            **kwargs
        )
        if not created and otp.roles != roles:
            otp.roles |= roles
            otp.save()

    def remove(self, perm, obj=None, roles=None):
        if obj is None:
            obj_id = NULL_OWNER_TO_PERMISSION_OBJECT_ID
            obj_ctype_id = NULL_OWNER_TO_PERMISSION_CTYPE_ID
        else:
            obj_id = obj.pk
            obj_ctype_id = ContentType.objects.get_for_model(obj)

        if isinstance(perm, str):
            perm_id = get_permission_id_by_name(perm)
        else:
            perm_id = perm.id

        OwnerToPermission = apps.get_model('protector', 'OwnerToPermission')
        try:
            otp = OwnerToPermission.objects.get(
                permission_id=perm_id, owner_object_id=self.instance.pk,
                owner_content_type=ContentType.objects.get_for_model(self.instance),
                object_id=obj_id, content_type_id=obj_ctype_id
            )
        except OwnerToPermission.DoesNotExist:
            return
        if roles is None or otp.roles == roles:
            otp.delete()
        else:
            otp.roles &= ~roles
            otp.save()
