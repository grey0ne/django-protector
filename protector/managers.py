from django.db import models
from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from protector.querysets import GenericUserToGroupQuerySet, PermissionQuerySet, \
    RestrictedQuerySet, OwnerToPermissionQuerySet, GenericGroupQuerySet
from protector.internals import get_default_group_ctype, DEFAULT_ROLE
from protector.helpers import get_permission_id_by_name, check_responsible_reason
from past.builtins import basestring


PermissionedManager = models.Manager.from_queryset(PermissionQuerySet)

RestrictedManager = models.Manager.from_queryset(RestrictedQuerySet)

GenericGroupManager = models.Manager.from_queryset(GenericGroupQuerySet)


class GenericUserToGroupManager(
    models.Manager.from_queryset(GenericUserToGroupQuerySet)
):
    use_in_migrations = True


class OwnerToPermissionManager(models.Manager.from_queryset(OwnerToPermissionQuerySet)):
    use_in_migrations = True


class UserGroupManager(models.Manager):

    def __init__(self, instance):
        super(UserGroupManager, self).__init__()
        self.instance = instance

    @check_responsible_reason
    def add(self, groups, reason, roles=None, responsible=None):
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        try:
            iter(groups)
        except TypeError:
            groups = [groups]
        for group in groups:
            roles = roles or group.DEFAULT_ROLE
            utg, created = GenericUserToGroup.objects.get_or_create(
                user=self.instance,
                group_id=group.pk,
                group_content_type=ContentType.objects.get_for_model(group),
                reason=reason,
                defaults={'responsible': responsible, 'roles': roles}
            )
            if not created and utg.roles != roles:
                utg.roles |= roles
                utg.save(reason=reason)

    @check_responsible_reason
    def remove(self, group, reason, roles=None, responsible=None):
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
            utg.delete(reason=reason, responsible=responsible)
        else:
            utg.roles &= ~roles
            utg.save(reason=reason)

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
            utg_qset = utg_qset.extra(where=["roles & %s != 0"], params=[roles])
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

    @check_responsible_reason
    def add(self, users, reason, roles=None, responsible=None):
        roles = roles or self.instance.DEFAULT_ROLE
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        try:
            iter(users)
        except TypeError:
            users = [users]
        for user in users:
            gug, created = GenericUserToGroup.objects.get_or_create(
                user=user, group_id=self.instance.id,
                group_content_type=ContentType.objects.get_for_model(self.instance),
                reason=reason,
                defaults={'roles': roles, 'responsible': responsible}
            )
            if not created and gug.roles != roles:
                gug.roles |= roles
                gug.save(reason=reason)

    @check_responsible_reason
    def remove(self, user, reason, roles=None, responsible=None):
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
            utg.delete(reason=reason, responsible=responsible)
        else:
            utg.roles &= ~roles
            utg.save(reason=reason)

    def by_role(self, roles):
        links = self.instance.users_relations.all()
        if roles is None:
            links = links.filter(roles__isnull=True)
        else:
            links = links.extra(where=["roles & %s != 0"], params=[roles])
        return get_user_model().objects.filter(id__in=links.values_list('user_id', flat=True))


class OwnerPermissionManager(models.Manager):

    def __init__(self, instance):
        super(OwnerPermissionManager, self).__init__()
        self.instance = instance

    def get_queryset(self):
        ctype = ContentType.objects.get_for_model(self.instance)
        Permission = apps.get_model('auth', 'Permission')
        return Permission.objects.filter(
            ownertopermission_generic_restriction_relations__owner_object_id__in=[self.instance.pk],
            ownertopermission_generic_restriction_relations__owner_content_type__in=[ctype]
        ).distinct()

    @check_responsible_reason
    def add(self, perm, reason, obj=None, roles=None, responsible=None):
        roles = roles or DEFAULT_ROLE
        kwargs = {
            'owner_object_id': self.instance.id,
            'owner_content_type': ContentType.objects.get_for_model(self.instance),
            'reason': reason,
            'defaults': {
                'responsible': responsible,
                'roles': roles,
            }
        }
        if isinstance(perm, basestring):
            kwargs['permission_id'] = get_permission_id_by_name(perm)
        else:
            kwargs['permission'] = perm

        if obj is not None:
            kwargs['object_id'] = obj.pk
            kwargs['content_type'] = ContentType.objects.get_for_model(obj)
        else:
            kwargs['object_id'] = None
            kwargs['content_type'] = None

        OwnerToPermission = apps.get_model('protector', 'OwnerToPermission')
        otp, created = OwnerToPermission.objects.get_or_create(**kwargs)
        if not created and otp.roles != roles:
            otp.roles |= roles
            otp.save(reason=reason)

    @check_responsible_reason
    def remove(self, perm, reason, obj=None, roles=None, responsible=None):
        if obj is None:
            obj_id = None
            obj_ctype_id = None
        else:
            obj_id = obj.pk
            obj_ctype_id = ContentType.objects.get_for_model(obj)

        if isinstance(perm, basestring):
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
            otp.delete(reason=reason, responsible=responsible)
        else:
            otp.roles &= ~roles
            otp.save(reason=reason)
