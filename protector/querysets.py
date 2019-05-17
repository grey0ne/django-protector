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


class HistorySavingBaseQuerySet(QuerySet):
    def __init__(self, model_queryset_name, **kwargs):
        self.protector_model = None
        self.history_model = None
        self.history_values = None
        protector_model_names = (
            {
                'model': 'OwnerToPermission',
                'history_model': 'HistoryOwnerToPermission'
            },
            {
                'model': 'GenericUserToGroup',
                'history_model': 'HistoryGenericUserToGroup'
            }
        )

        for model_name in protector_model_names:
            if model_name['model'] in model_queryset_name:
                self.protector_model = apps.get_model('protector', model_name['model'])
                self.history_model = apps.get_model('protector', model_name['history_model'])

        if self.history_model is None or self.protector_model is None:
            raise ValidationError('Unknown protector model')

        if self.protector_model.__name__ == 'OwnerToPermission':
            self.history_values = OWNER_VALUES_TO_SAVE_FOR_HISTORY
        elif self.protector_model.__name__ == 'GenericUserToGroup':
            self.history_values = GENERIC_GROUP_VALUES_TO_SAVE_FOR_HISTORY

        super(HistorySavingBaseQuerySet, self).__init__(**kwargs)

    def delete(self, initiator, reason):
        histories_to_create = list()

        if not isinstance(initiator, get_user_model()):
            raise ValidationError('Initiator should be an instance of User model')
        if not isinstance(reason, str) or not len(reason):
            raise ValidationError('You should point the reason for this action')

        objs_to_delete = self.values(*self.history_values)

        for obj in objs_to_delete:
            obj.update({
                'initiator': initiator,
                'reason': reason,
                'change_type': self.history_model.TYPE_REMOVE,
            })
            histories_to_create.append(self.history_model(**obj))

        self.history_model.objects.bulk_create(histories_to_create)

        super(HistorySavingBaseQuerySet, self).delete()

    def create(self, **kwargs):
        if 'initiator' not in kwargs and 'initiator_id' not in kwargs:
            raise ValidationError('You should indicate, who was the initiator of this action')
        if 'initiator' in kwargs and not isinstance(kwargs['initiator'], get_user_model()):
            raise ValidationError('Initiator is not an instance of user model')
        if 'initiator_id' in kwargs and not isinstance(kwargs['initiator_id'], int):
            raise ValidationError('Initiator ID is not an instance of int class')

        if 'reason' not in kwargs or not len(kwargs['reason']) or not isinstance(kwargs['reason'], str):
            raise ValidationError('You should point the reason for this action')

        history_kwargs = deepcopy(kwargs)
        history_kwargs.update({'change_type': self.history_model.TYPE_ADD})

        try:
            del kwargs['reason']
            if 'initiator' in kwargs:
                del kwargs['initiator']
            else:
                del kwargs['initiator_id']
        except KeyError:
            pass

        created_obj = super(HistorySavingBaseQuerySet, self).create(**kwargs)
        self.history_model.objects.create(**history_kwargs)

        user_ctype = get_user_ctype()
        if 'owner_content_type' in kwargs and kwargs['owner_content_type'] == user_ctype\
                or 'owner_content_type_id' in kwargs and kwargs['owner_content_type_id'] == user_ctype.id:
            # Here is a bit of denormalization
            # User is a part of group of his own
            # This is done to drastically improve perm checking performance
            GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
            GenericUserToGroup.objects.get_or_create(
                reason=history_kwargs['reason'],
                initiator_id=history_kwargs['initiator'].id\
                    if 'initiator' in history_kwargs else history_kwargs['initiator_id'],
                group_id=kwargs['owner_object_id'],
                group_content_type_id=kwargs['owner_content_type'].id\
                    if 'owner_content_type' in kwargs else kwargs['owner_content_type_id'],
                user_id=kwargs['owner_object_id'],
                roles=1
            )

        return created_obj

    def get_or_create(self, defaults=None, **kwargs):
        if 'initiator_id' not in kwargs and 'initiator' not in kwargs:
            raise ValidationError(u'Indicate initiator in case creation occurs')
        if 'reason' not in kwargs:
            raise ValidationError(u'Point out the reason in case creation occurs')

        get_kwargs = deepcopy(kwargs)
        try:
            del get_kwargs['reason']
            if 'initiator_id' in kwargs:
                del get_kwargs['initiator_id']
            elif 'initiator' in kwargs:
                del get_kwargs['initiator']
        except KeyError:
            pass

        try:
            result = super(HistorySavingBaseQuerySet, self).get_or_create(defaults=defaults, **get_kwargs)
        except ValidationError:
            # in case there's no such record in db, create will raise Validation error
            # due to absence of initiator and reason fields.
            # Here we explicitly create new record with such fields.
            result = self.create(**kwargs)
        return (result, True) if not isinstance(result, tuple) else result


class GenericUserToGroupQuerySet(HistorySavingBaseQuerySet):
    def __init__(self, **kwargs):
        super(GenericUserToGroupQuerySet, self).__init__(
            model_queryset_name=self.__class__.__name__,
            **kwargs
        )

    def by_role(self, roles):
        utg_table_name = self.model._meta.db_table
        return self.extra(
            where=["{utg_table}.roles & %s".format(utg_table=utg_table_name)],
            params=[roles]
        )


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


class OwnerToPermissionQuerySet(HistorySavingBaseQuerySet):
    def __init__(self, **kwargs):
        super(OwnerToPermissionQuerySet, self).__init__(
            model_queryset_name=self.__class__.__name__,
            **kwargs
        )

    def without_obj_perms(self):
        return self.filter(
            object_id__isnull=True,
            content_type_id__isnull=True
        )

    def update(self, **kwargs):
        if kwargs and self.filter(**kwargs).exists():
            raise ValidationError('Duplicate with kwargs: {}'.format(kwargs))
        super(OwnerToPermissionQuerySet, self).update(**kwargs)


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
