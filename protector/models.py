# -*- coding: utf-8 -*-
from django.db import models
from django.db.models.query import QuerySet
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.contrib import auth
from django.contrib.auth.models import Permission
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes import generic
from django.core.cache import cache
from django.utils.translation import ugettext_lazy as _
from mptt.models import MPTTModel, TreeForeignKey


def get_user_ctype():
    return ContentType.objects.get_for_model(get_user_model())

#  Need this to avoid null values in OwnerToPermission table
NULL_OWNER_TO_PERMISSION_OBJECT_ID = 0
NULL_OWNER_TO_PERMISSION_CTYPE_ID = 1  # That is ContentType ctype id

ADD_PERMISSION_PERMISSION = 'add_permission'
VIEW_RESTRICTED_OBJECTS = 'view_restricted_objects'

VIEW_PERMISSION_NAME = 'protector.{0}'.format(VIEW_RESTRICTED_OBJECTS)

#  Form a from clause for all permission related to their owners
#  role of user in group must not be empty
#  if permission roles is empty than it is applied to all roles in group

DEFAULT_ROLE = 1


def get_view_permission():
    codename = VIEW_RESTRICTED_OBJECTS
    if Restricted._view_perm is None:
        ctype = ContentType.objects.get_for_model(OwnerToPermission)
        Restricted._view_perm = Permission.objects.get(
            codename=codename, content_type=ctype
        )
    return Restricted._view_perm


def get_permission_owners_query():
    """
        This functions generate SQL statement for selecting groups and perms.
        Sadly, Django doesn't support join in ORM
        Should not select users that hasn't got any role
        Should select perms that assigned to any role
    """
    owners_query = """
        {group_table_name!s} gug LEFT JOIN
        {owner_table_name!s} op ON
            gug.group_id = op.owner_object_id AND
            gug.group_content_type_id = op.owner_content_type_id AND
            gug.roles & op.roles LEFT JOIN
        {global_table_name!s} gl ON
            gl.content_type_id = gug.group_content_type_id AND
            gl.roles & gug.roles
    """
    return owners_query.format(
        owner_table_name=OwnerToPermission._meta.db_table,
        group_table_name=GenericUserToGroup._meta.db_table,
        global_table_name=GenericGlobalPerm._meta.db_table,
        null_owner_id=NULL_OWNER_TO_PERMISSION_OBJECT_ID
    )


class GenericGlobalPerm(models.Model):
    """
        This model is for defining template-like permissions
        e.g. Every blog moderator could edit his blog
    """
    content_type = models.ForeignKey(
        ContentType, related_name='global_perms',
        default=NULL_OWNER_TO_PERMISSION_CTYPE_ID
    )
    roles = models.IntegerField(verbose_name=_('roles'), default=DEFAULT_ROLE)
    permission = models.ForeignKey(Permission)

    class Meta:
        verbose_name = _('global group permission')
        verbose_name_plural = _('global group permissions')
        unique_together = ('content_type', 'permission')


class GenericUserToGroupQuerySet(QuerySet):
    def by_role(self, roles):
        utg_table_name = self.model._meta.db_table
        return self.extra(
            where=["{utg_table}.roles & %s".format(utg_table=utg_table_name)],
            params=[roles]
        )


GenericUserToGroupManager = models.Manager.from_queryset(GenericUserToGroupQuerySet)


class GenericUserToGroup(models.Model):
    """
        This models is used for linking user to any possible group
        User can have only one link to group
        In case of multiple roles bitmasks is used
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='generic_group_relations'
    )
    roles = models.IntegerField(verbose_name=_('roles'), blank=True, null=True)
    group_id = models.PositiveIntegerField()
    group_content_type = models.ForeignKey(ContentType)
    group = generic.GenericForeignKey('group_content_type', 'group_id')
    date_joined = models.DateTimeField(verbose_name=_('date joined'), auto_now_add=True)
    responsible = models.ForeignKey(
        verbose_name=_('responsible'),
        to=settings.AUTH_USER_MODEL, related_name='created_group_relations',
        blank=True, null=True
    )

    objects = GenericUserToGroupManager()

    class Meta:
        verbose_name = _('user to group link')
        verbose_name_plural = _('user to group links')
        unique_together = ('group_id', 'group_content_type', 'user')

    def __unicode__(self):
        return "{app}.{model}.{group_id} - {username}".format(
            app=self.group_content_type.app_label,
            model=self.group_content_type.model,
            group_id=self.group_id,
            username=self.user.username
        )


class OwnerToPermissionQuerySet(QuerySet):
    def without_obj_perms(self):
        return self.filter(
            object_id=NULL_OWNER_TO_PERMISSION_OBJECT_ID,
            content_type_id=NULL_OWNER_TO_PERMISSION_CTYPE_ID
        )


OwnerToPermissionManager = models.Manager.from_queryset(OwnerToPermissionQuerySet)


class OwnerToPermission(models.Model):
    """
        This model is two-way generic many-to-many link from owner_object to owned object
        Multiple links from owner to object is supported i.e. different permissions
    """
    ADD_PERMISSION = ADD_PERMISSION_PERMISSION
    object_id = models.PositiveIntegerField(
        verbose_name=_('object id'),
        default=NULL_OWNER_TO_PERMISSION_OBJECT_ID
    )
    content_type = models.ForeignKey(
        verbose_name=_('object type'),
        to=ContentType, related_name='restriction_group_relations',
        default=NULL_OWNER_TO_PERMISSION_CTYPE_ID
    )
    content_object = generic.GenericForeignKey('content_type', 'object_id')
    owner_object_id = models.PositiveIntegerField(verbose_name=_('owner id'))
    owner_content_type = models.ForeignKey(
        verbose_name=_('owner type'),
        to=ContentType, related_name='restricted_object_relations'
    )
    owner = generic.GenericForeignKey('owner_content_type', 'owner_object_id')
    permission = models.ForeignKey(
        verbose_name=_('permission'),
        to=Permission, related_name='generic_restriction_relations'
    )
    date_issued = models.DateTimeField(verbose_name=_('date issued'), auto_now_add=True)
    responsible = models.ForeignKey(
        verbose_name=_('responsible'),
        to=settings.AUTH_USER_MODEL, related_name='created_permission_relations',
        blank=True, null=True
    )
    roles = models.IntegerField(verbose_name=_('roles'), default=DEFAULT_ROLE)

    objects = OwnerToPermissionManager()

    class Meta:
        verbose_name = _('owner to permission link')
        verbose_name_plural = _('owner to permission links')
        index_together = (
            ['owner_content_type', 'owner_object_id'],
            ['content_type', 'object_id', 'permission']
        )
        unique_together = (
            'content_type', 'object_id',
            'owner_content_type', 'owner_object_id',
            'permission'
        )
        permissions = (
            (ADD_PERMISSION_PERMISSION, _('add permission')),
            (VIEW_RESTRICTED_OBJECTS, _('view restricted objects')),
        )

    def __unicode__(self):
        if self.object_id == 0:
            ctype = None
        else:
            ctype = self.content_type
        result = "{app}.{model}.{pk} ".format(
            app=self.owner_content_type.app_label,
            model=self.owner_content_type.model,
            pk=self.owner_object_id,
        )
        if self.object_id != 0:  # real object not global permission
            result += "- {app}.{model}.{pk}. ".format(
                app=ctype.app_label if ctype else '',
                model=ctype.model if ctype else '',
                pk=self.object_id or '',
            )
        if self.roles:
            result += "Roles {roles}. ".format(roles=self.roles)
        result += "Permission {perm}".format(perm=self.permission.codename)
        return result

    def save(self, *args, **kwargs):
        if self.owner_content_type == get_user_ctype():
            # Here is a bit of denormalization
            # User is a part of group of his own
            # This is done to drastically improve perm checking performance
            GenericUserToGroup.objects.get_or_create(
                group_id=self.owner_object_id,
                group_content_type=self.owner_content_type,
                user_id=self.owner_object_id,
                roles=1
            )
        super(OwnerToPermission, self).save(*args, **kwargs)


class GenericPermsMixin(models.Model):
    """
        Mixin is can be used to easily retrieve all owners of permissions to this object
    """
    permission_relations = generic.GenericRelation(
        OwnerToPermission, content_type_field='owner_content_type',
        object_id_field='owner_object_id'
    )

    permissions = None

    def __init__(self, *args, **kwargs):
        super(GenericPermsMixin, self).__init__(*args, **kwargs)
        self.permissions = OwnerPermissionManager(self)

    class Meta:
        abstract = True


class UserGenericPermsMixin(GenericPermsMixin):
    """
        Mixin is used for replacing standard user authorization mechanism
        Also mimics all methods of standard user and is completely compatible
    """
    is_superuser = models.BooleanField(
        verbose_name=_('superuser status'), default=False,
        help_text=_(
            'Designates that this user has all permissions without explicitly assigning them.'
        )
    )

    def __init__(self, *args, **kwargs):
        super(UserGenericPermsMixin, self).__init__(*args, **kwargs)
        self.groups = UserGroupManager(self)

    class Meta:
        abstract = True

    def get_group_permissions(self, obj=None):
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_group_permissions"):
                permissions.update(backend.get_group_permissions(self, obj))
        return permissions

    def get_all_permissions(self, obj=None):
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_all_permissions"):
                permissions.update(backend.get_all_permissions(self, obj))
        return permissions

    def has_perm(self, perm, obj=None):
        if self.is_active and self.is_superuser:
            return True

        for backend in auth.get_backends():
            if not hasattr(backend, 'has_perm'):
                continue
            try:
                if backend.has_perm(self, perm, obj):
                    return True
            except PermissionDenied:
                return False
        return False

    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions. If
        object is passed, it checks if the user has all required perms for this
        object.
        """
        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permissions in the given app label.
        Uses pretty much the same logic as has_perm, above.
        """
        if self.is_active and self.is_superuser:
            return True

        for backend in auth.get_backends():
            if not hasattr(backend, 'has_module_perms'):
                continue
            try:
                if backend.has_module_perms(self, app_label):
                    return True
            except PermissionDenied:
                return False
        return False


class AbstractGenericGroup(GenericPermsMixin):
    """
        Base model for all Groups
        Inherit your model from that to enable generic group features
    """
    PARTICIPANT = 1
    ROLES = (
        (PARTICIPANT, _('Participant')),
    )
    DEFAULT_ROLE = PARTICIPANT

    users_relations = generic.GenericRelation(
        GenericUserToGroup, content_type_field='group_content_type',
        object_id_field='group_id'
    )

    class Meta:
        abstract = True

    def __init__(self, *args, **kwargs):
        super(AbstractGenericGroup, self).__init__(*args, **kwargs)
        self.users = GroupUserManager(self)

    def get_roles(self, user):
        try:
            user_roles = self.users_relations.values('roles').get(user=user)['roles']
        except GenericUserToGroup.DoesNotExist:
            return []
        else:
            return [role[0] for role in self.ROLES if role[0] & user_roles]


def filter_queryset_by_permission(qset, user, permission):
    perm_id = get_permission_id_by_name(permission)
    if user.has_perm(permission):
        return qset.all()
    if user.id is None or perm_id is None:
        return qset.none()
    condition = _get_permission_filter(qset, user.id, perm_id)
    return qset.extra(where=[condition])


def _get_restriction_filter(qset, user_id, perm_id):
    if hasattr(qset, 'get_restriction_id_field'):
        obj_id_field = qset.get_restriction_id_field()
    else:
        obj_id_field = "{table_name!s}.restriction_id".format(table_name=qset.model._meta.db_table)
    if hasattr(qset, 'get_restriction_ctype_id_field'):
        ctype_id_field = qset.get_restriction_ctype_id_field()
    else:
        ctype_id_field = "{table_name!s}.restriction_content_type_id".format(
            table_name=qset.model._meta.db_table
        )
    return _get_filter_by_perm_condition(qset, user_id, perm_id, obj_id_field, ctype_id_field)


def _get_permission_filter(qset, user_id, perm_id):
    if hasattr(qset, 'get_obj_id_field'):
        obj_id_field = qset.get_obj_id_field()
    else:
        obj_id_field = "{table_name!s}.id".format(table_name=qset.model._meta.db_table)
    if hasattr(qset, 'get_ctype_id_field'):
        ctype_id_field = qset.get_ctype_id_field()
    else:
        ctype_id_field = str(ContentType.objects.get_for_model(qset.model).id)
    return _get_filter_by_perm_condition(qset, user_id, perm_id, obj_id_field, ctype_id_field)


def _generate_filter_condition(user_id, perm_id, ctype_id_field, obj_id_field):
    condition = """
        gug.user_id = {user_id!s} AND (
            (
                op.permission_id = {perm_id!s} AND
                op.content_type_id = {ctype_id_field!s} AND
                (op.object_id = {obj_id_field!s} OR op.object_id = {null_owner_id!s})
            ) OR (
                gl.permission_id = {perm_id!s} AND
                gl.content_type_id = {ctype_id_field!s} AND
                gug.group_id = {obj_id_field!s}
            )
        )
    """
    return condition.format(
        user_id=user_id, perm_id=perm_id,
        null_owner_id=NULL_OWNER_TO_PERMISSION_OBJECT_ID,
        obj_id_field=obj_id_field,
        ctype_id_field=ctype_id_field
    )


def _get_filter_by_perm_condition(qset, user_id, perm_id, obj_id_field, ctype_id_field):
    # here we brake some rules about sql sanitizing
    # it is a shame, but this is an internal function so we can live with it
    condition = "EXISTS (SELECT op.id FROM {permission_owners} WHERE {filter_condition})"
    return condition.format(
        permission_owners=get_permission_owners_query(),
        filter_condition=_generate_filter_condition(
            user_id, perm_id, ctype_id_field, obj_id_field
        )
    )


class PermissionQuerySet(QuerySet):
    """
        Queryset is used for filtering any queryset by user permissions on its objects
    """
    def filter_by_permission(self, user, permission):
        return filter_queryset_by_permission(self, user, permission)


PermissionedManager = models.Manager.from_queryset(PermissionQuerySet)


class RestrictedQuerySet(PermissionQuerySet):
    """
        Queryset is used for filtering objects not visible to user
    """

    def visible(self, user=None):
        if user is None:
            return self.filter(restriction_id__isnull=True)
        if user.has_perm(VIEW_PERMISSION_NAME):
            return self
        if user.id is None:
            return self.filter(restriction_id__isnull=True)
        condition = self._get_visible_condition(user.id, get_view_permission().id)
        return self.extra(where=[condition])

    def _get_visible_condition(self, user_id, perm_id):
        condition = """
            {table_name!s}.restriction_id IS NULL OR
        """
        condition += _get_restriction_filter(self, user_id, perm_id)
        condition = condition.format(table_name=self.model._meta.db_table)
        return condition


RestrictedManager = models.Manager.from_queryset(RestrictedQuerySet)


class Restriction(MPTTModel, models.Model):
    """
        This model contains resriction hierarchy
    """
    object_id = models.PositiveIntegerField(blank=False, null=False)
    content_type = models.ForeignKey(ContentType, blank=False, null=False)
    restricted_object = generic.GenericForeignKey('content_type', 'object_id')

    parent = TreeForeignKey(
        'self', verbose_name=_('parent object'),
        null=True, blank=True, related_name='children'
    )

    class Meta:
        verbose_name = _('Object restriction')
        verbose_name_plural = _('Objects restrictions')
        unique_together = (('object_id', 'content_type'), )

    def __unicode__(self):
        return '{app}.{model} {pk}'.format(
            app=self.content_type.app_label,
            model=self.content_type.model,
            pk=self.object_id
        )


class Restricted(models.Model):
    """
        Inherit your model from that to enable visiblity restrictions
    """
    VIEW_PERMISSION_NAME = VIEW_PERMISSION_NAME

    restriction_id = models.PositiveIntegerField(blank=True, null=True)
    restriction_content_type = models.ForeignKey(
        ContentType, blank=True, null=True, related_name="%(app_label)s_%(class)s_restrictions"
    )
    restriction = generic.GenericForeignKey('restriction_content_type', 'restriction_id')

    objects = RestrictedManager()
    _view_perm = None

    class Meta:
        abstract = True

    @classmethod
    def get_view_permission(cls):
        return get_view_permission()

    def get_parent_object(self):
        return None

    def get_restriction_obj(self):
        return Restriction.objects.get_or_create(
            object_id=self.pk,
            content_type=ContentType.objects.get_for_model(self)
        )[0]

    def get_restriction_descendants(self):
        ctype_dict = {}
        restriction_obj = self.get_restriction_obj()
        descendants = restriction_obj.get_descendants()
        ctype_dict = {}
        for restriction in descendants:
            ctype_id = restriction.content_type_id
            if ctype_id not in ctype_dict:
                ctype_dict[ctype_id] = []
            ctype_dict[ctype_id].append(restriction.object_id)
        return ctype_dict

    def restrict(self):
        # method restricts all objects down by restriction heirarachy
        if self.restriction != self:
            current_restriction_id = self.restriction_id
            current_restriction_ctype_id = self.restriction_content_type_id
            self.restriction = self
            if self.pk is not None:
                ctype_dict = self.get_restriction_descendants()
                for ctype_id, object_ids in ctype_dict.iteritems():
                    ctype = ContentType.objects.get_for_id(ctype_id)
                    objs = ctype.model_class().objects.filter(
                        pk__in=object_ids, restriction_id=current_restriction_id,
                        restriction_content_type_id=current_restriction_ctype_id
                    )
                    objs.update(
                        restriction_id=self.id,
                        restriction_content_type=ContentType.objects.get_for_model(self)
                    )
            self.save()

    def unrestrict(self):
        if self.restriction is None:
            return
        ctype_dict = self.get_restriction_descendants()
        current_restriction_id = self.restriction_id
        current_restriction_ctype_id = self.restriction_content_type_id
        for ctype_id, object_ids in ctype_dict.iteritems():
            ctype = ContentType.objects.get_for_id(ctype_id)
            objs = ctype.model_class().objects.filter(
                pk__in=object_ids, restriction_id=current_restriction_id,
                restriction_content_type_id=current_restriction_ctype_id
            )
            # take only objects that restricted by same object as self
            objs.update(
                restriction_id=None,
                restriction_content_type=None
            )
        self.restriction = None
        self.save()

    def is_visible(self, user=None):
        return self.restriction is None or (user is not None and user.has_perm(
            VIEW_PERMISSION_NAME, self.restriction
        ))

    def is_restricted(self):
        return self.restriction_id is not None

    def inherit_restriction(self):
        parent_object = self.get_parent_object()
        if parent_object is not None and isinstance(parent_object, Restricted):
            self.restriction_id = parent_object.restriction_id
            self.restriction_content_type_id = parent_object.restriction_content_type_id

    def generate_restriction(self):
        parent_object = self.get_parent_object()
        self_restriction, created = Restriction.objects.get_or_create(
            object_id=self.pk, content_type=ContentType.objects.get_for_model(self)
        )
        if parent_object is not None and isinstance(parent_object, Restricted):
            parent_restriction = Restriction.objects.get(
                object_id=parent_object.id,
                content_type=ContentType.objects.get_for_model(parent_object)
            )
            self_restriction.parent = parent_restriction
            self_restriction.save()

    def save(self, *args, **kwargs):
        created = self.pk is None
        if created:
            self.inherit_restriction()
        super(Restricted, self).save(*args, **kwargs)
        if created and self.pk is not None:
            self.generate_restriction()
            # Create a corresponding restriction object and link it to parent

    def add_viewer(self, viewer, responsible=None, roles=None):
        roles = roles or DEFAULT_ROLE
        otp, created = OwnerToPermission.objects.get_or_create(
            object_id=self.pk,
            content_type=ContentType.objects.get_for_model(self),
            owner_object_id=viewer.pk,
            owner_content_type=ContentType.objects.get_for_model(viewer),
            permission=get_view_permission(),
            defaults={'responsible': responsible, 'roles': roles}
        )
        if not created and otp.roles != roles:
            otp.roles |= roles
            otp.save()


def get_default_group_ctype():
    return ContentType.objects.get_by_natural_key(
        *settings.PROTECTOR_GENERIC_GROUP.lower().split('.')
    )


class UserGroupManager(models.Manager):

    def __init__(self, instance):
        super(UserGroupManager, self).__init__()
        self.instance = instance

    def add(self, group, responsible=None, roles=None):
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
        if group_type is None:
            group_type = get_default_group_ctype()
        return group_type.model_class().objects.filter(
            pk__in=GenericUserToGroup.objects.filter(
                group_content_type=group_type,
                user=self.instance
            ).values_list('group_id')
        )

    def by_ctype(self, group_type, roles=None):
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

    def add(self, user, roles=None, responsible=None):
        roles = roles or self.instance.DEFAULT_ROLE
        gug, created = GenericUserToGroup.objects.get_or_create(
            user=user, group_id=self.instance.id,
            group_content_type=ContentType.objects.get_for_model(self.instance),
            defaults={'roles': roles, 'responsible': responsible}
        )
        if not created:
            gug.roles |= roles
            gug.save()

    def remove(self, user, roles=None):
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
        return Permission.objects.filter(
            generic_restriction_relations__owner_object_id__in=[self.instance.pk],
            generic_restriction_relations__owner_content_type__in=[ctype]
        ).distinct()

    def add(self, perm, obj=None, responsible=None, roles=None):
        roles = roles or DEFAULT_ROLE
        kwargs = {
            'owner_object_id': self.instance.id,
            'owner_content_type': ContentType.objects.get_for_model(self.instance),
            'permission': perm,
            'defaults': {'responsible': responsible, 'roles': roles}
        }
        if obj is not None:
            kwargs['object_id'] = obj.pk
            kwargs['content_type'] = ContentType.objects.get_for_model(obj)
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
        try:
            otp = OwnerToPermission.objects.get(
                permission=perm, owner_object_id=self.instance.pk,
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


def get_permission_id_by_name(permission):
    cache_key = 'permission_id_cache_' + permission
    perm_id = cache.get(cache_key, None)
    if perm_id is None:
        try:
            perm_id = Permission.objects.get(
                codename=permission.split('.')[1],
                content_type__app_label=permission.split('.')[0]
            ).id
        except Permission.DoesNotExist:
            return None
        cache.set(cache_key, perm_id)
    return perm_id


class PermAnnotatedMixin(QuerySet):

    annotate_perms_for_user = None

    def annotate_perms(self, user):
        new_qset = self.all()
        new_qset.annotate_perms_for_user = user
        return new_qset

    def _fetch_all(self):
        super(PermAnnotatedMixin, self)._fetch_all()
