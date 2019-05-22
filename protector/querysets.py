from copy import deepcopy
from django.db.models.query import QuerySet
from django.db.models import F
from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from protector.internals import (
    VIEW_PERMISSION_NAME,
    OWNER_VALUES_TO_SAVE_FOR_HISTORY,
    GENERIC_GROUP_VALUES_TO_SAVE_FOR_HISTORY,
    REASON_VALIDATION_ERROR,
    _get_restriction_filter,
    get_user_ctype,
)
from protector.helpers import filter_queryset_by_permission, get_view_permission


class PermissionQuerySet(QuerySet):
    """
        Queryset is used for filtering any queryset by user permissions on its objects
    """
    def filter_by_permission(self, user, permission):
        return filter_queryset_by_permission(self, user, permission)


class GenericUserToGroupQuerySet(QuerySet):
    def by_role(self, roles):
        utg_table_name = self.model._meta.db_table
        return self.extra(
            where=["{utg_table}.roles & %s".format(utg_table=utg_table_name)],
            params=[roles]
        )

    def delete(self, reason, initiator=None):
        histories_to_create = list()
        HistoryGenericUserToGroup = apps.get_model('protector', 'HistoryGenericUserToGroup')

        if not isinstance(reason, str) or not len(reason):
            raise ValidationError(REASON_VALIDATION_ERROR)

        objs_to_delete = self.values(*GENERIC_GROUP_VALUES_TO_SAVE_FOR_HISTORY)

        for obj in objs_to_delete:
            obj.update({
                'initiator': initiator,
                'reason': reason,
                'change_type': HistoryGenericUserToGroup.TYPE_REMOVE,
            })
            histories_to_create.append(HistoryGenericUserToGroup(**obj))

        HistoryGenericUserToGroup.objects.bulk_create(histories_to_create)

        super(GenericUserToGroupQuerySet, self).delete()

    def create(self, **kwargs):
        if 'initiator' in kwargs:
            if not kwargs['initiator']:
                del kwargs['initiator']
            elif not isinstance(kwargs['initiator'], get_user_model()):
                raise ValidationError('Initiator is not an instance of user model')

        if 'reason' not in kwargs or not len(kwargs['reason']) or not isinstance(kwargs['reason'], str):
            raise ValidationError(REASON_VALIDATION_ERROR)

        HistoryGenericUserToGroup = apps.get_model('protector', 'HistoryGenericUserToGroup')

        history_kwargs = deepcopy(kwargs)
        history_kwargs.update({'change_type': HistoryGenericUserToGroup.TYPE_ADD})

        try:
            del kwargs['reason']
            if 'initiator' in kwargs:
                del kwargs['initiator']
        except KeyError:
            pass
        created_obj = super(GenericUserToGroupQuerySet, self).create(**kwargs)
        HistoryGenericUserToGroup.objects.create(**history_kwargs)

        return created_obj

    def get_or_create(self, defaults=None, **kwargs):
        if 'reason' not in kwargs:
            raise ValidationError(u'Point out the reason in case creation occurs')

        get_kwargs = deepcopy(kwargs)
        try:
            del get_kwargs['reason']
            if 'initiator' in kwargs:
                del get_kwargs['initiator']
        except KeyError:
            pass
        try:
            result = super(GenericUserToGroupQuerySet, self).get_or_create(defaults=defaults, **get_kwargs)
        except ValidationError:
            # in case there's no such record in db, create will raise Validation error
            # due to absence reason fields.
            # Here we explicitly create new record with such fields.
            if defaults:
                kwargs.update(defaults)
            result = self.create(**kwargs)
        return (result, True) if not isinstance(result, tuple) else result


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


class OwnerToPermissionQuerySet(QuerySet):
    def without_obj_perms(self):
        return self.filter(
            object_id__isnull=True,
            content_type_id__isnull=True
        )

    def delete(self, reason, initiator=None):
        histories_to_create = list()

        if not isinstance(reason, str) or not len(reason):
            raise ValidationError(REASON_VALIDATION_ERROR)

        objs_to_delete = self.values(*OWNER_VALUES_TO_SAVE_FOR_HISTORY)
        HistoryOwnerToPermission = apps.get_model('protector', 'HistoryOwnerToPermission')

        for obj in objs_to_delete:
            obj.update({
                'initiator': initiator,
                'reason': reason,
                'change_type': HistoryOwnerToPermission.TYPE_REMOVE,
            })
            histories_to_create.append(HistoryOwnerToPermission(**obj))

        HistoryOwnerToPermission.objects.bulk_create(histories_to_create)

        super(OwnerToPermissionQuerySet, self).delete()

    def create(self, **kwargs):
        if 'initiator' in kwargs:
            if not kwargs['initiator']:
                del kwargs['initiator']
            elif not isinstance(kwargs['initiator'], get_user_model()):
                raise ValidationError('Initiator is not an instance of user model')

        if 'reason' not in kwargs or not len(kwargs['reason']) or not isinstance(kwargs['reason'], str):
            raise ValidationError(REASON_VALIDATION_ERROR)

        HistoryOwnerToPermission = apps.get_model('protector', 'HistoryOwnerToPermission')

        history_kwargs = deepcopy(kwargs)
        history_kwargs.update({'change_type': HistoryOwnerToPermission.TYPE_ADD})

        try:
            del kwargs['reason']
            if 'initiator' in kwargs:
                del kwargs['initiator']
        except KeyError:
            pass
        created_obj = super(OwnerToPermissionQuerySet, self).create(**kwargs)
        HistoryOwnerToPermission.objects.create(**history_kwargs)

        user_ctype = get_user_ctype()
        if 'owner_content_type' in kwargs and kwargs['owner_content_type'] == user_ctype\
                or 'owner_content_type_id' in kwargs and kwargs['owner_content_type_id'] == user_ctype.id:
            # Here is a bit of denormalization
            # User is a part of group of his own
            # This is done to drastically improve perm checking performance
            GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
            GenericUserToGroup.objects.get_or_create(
                reason=history_kwargs['reason'],
                initiator=history_kwargs['initiator'] if 'initiator' in kwargs else None,
                group_id=kwargs['owner_object_id'],
                group_content_type_id=kwargs['owner_content_type'].id\
                    if 'owner_content_type' in kwargs else kwargs['owner_content_type_id'],
                user_id=kwargs['owner_object_id'],
                roles=1
            )

        return created_obj

    def get_or_create(self, defaults=None, **kwargs):
        if 'reason' not in kwargs:
            raise ValidationError(u'Point out the reason in case creation occurs')

        get_kwargs = deepcopy(kwargs)
        try:
            del get_kwargs['reason']
            if 'initiator' in kwargs:
                del get_kwargs['initiator']
        except KeyError:
            pass
        try:
            result = super(OwnerToPermissionQuerySet, self).get_or_create(defaults=defaults, **get_kwargs)
        except ValidationError:
            # in case there's no such record in db, create will raise Validation error
            # due to absence reason fields.
            # Here we explicitly create new record with such fields.
            if defaults:
                kwargs.update(defaults)
            result = self.create(**kwargs)
        return (result, True) if not isinstance(result, tuple) else result


class PermAnnotatedMixin(QuerySet):

    annotate_perms_for_user = None

    def annotate_perms(self, user):
        new_qset = self.all()
        new_qset.annotate_perms_for_user = user
        return new_qset

    def _fetch_all(self):
        super(PermAnnotatedMixin, self)._fetch_all()


class GenericGroupQuerySet(QuerySet):
    def update(self, *args, **kwargs):
        # Automatically update group links
        # WARNING it does NOT automatically delete stale perms
        super(GenericGroupQuerySet, self).update(*args, **kwargs)
        ctype = ContentType.objects.get_for_model(self.model)
        links_to_create = []
        GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
        for field, roles in self.model.MEMBER_FOREIGN_KEY_FIELDS:
            if field in kwargs:
                ids = set(self.values_list('id', flat=True))

                links_qset = GenericUserToGroup.objects.filter(
                    group_id__in=ids, group_content_type=ctype,
                    user=kwargs[field]
                )
                links_qset.update(roles=F('roles').bitand(roles))
                existing_ids = set(links_qset.values_list('group_id', flat=True))
                for id in (ids - existing_ids):
                    links_to_create.append(GenericUserToGroup(
                        group_id=id, group_content_type=ctype, user=kwargs[field],
                        responsible=kwargs[field], roles=roles
                    ))
        if links_to_create:
            GenericUserToGroup.objects.bulk_create(links_to_create)

    def create(self, **kwargs):
        instance = super(GenericGroupQuerySet, self).create(**kwargs)
        instance._update_member_foreign_key()
        return instance
