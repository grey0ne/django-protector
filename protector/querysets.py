from __future__ import unicode_literals

from copy import deepcopy
from django.db.models.query import QuerySet
from django.db.models import F
from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from protector.exceptions import NoReasonSpecified
from protector.internals import (
    VIEW_PERMISSION_NAME,
    _get_restriction_filter,
)
from protector.helpers import filter_queryset_by_permission, get_view_permission, check_responsible_reason
from protector.reserved_reasons import GENERIC_GROUP_UPDATE_REASON


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

    @check_responsible_reason
    def delete(self, **kwargs):
        reason = kwargs.get('reason')
        responsible = kwargs.get('responsible')
        histories_to_create = list()
        HistoryGenericUserToGroup = apps.get_model('protector', 'HistoryGenericUserToGroup')

        objs_to_delete = self.values(*self.model().values_to_save_for_history().keys())

        for obj in objs_to_delete:
            obj.update({
                'reason': reason,
                'responsible': responsible,
                'change_type': HistoryGenericUserToGroup.TYPE_REMOVE,
            })
            histories_to_create.append(HistoryGenericUserToGroup(**obj))

        HistoryGenericUserToGroup.objects.bulk_create(histories_to_create)

        return super(GenericUserToGroupQuerySet, self).delete()

    @check_responsible_reason
    def bulk_create(self, objs, batch_size=None, **kwargs):
        HistoryGenericUserToGroup = apps.get_model('protector', 'HistoryGenericUserToGroup')

        created_objs = super(GenericUserToGroupQuerySet, self).bulk_create(objs, batch_size=batch_size)

        hist_objs = deepcopy(objs)
        hist_objs_to_create = list()
        for obj in hist_objs:
            obj = obj.values_to_save_for_history()
            obj.update({
                'change_type': HistoryGenericUserToGroup.TYPE_ADD,
                'reason': kwargs.get('reason'),
            })
            hist_objs_to_create.append(HistoryGenericUserToGroup(**obj))

        HistoryGenericUserToGroup.objects.bulk_create(hist_objs_to_create, batch_size=batch_size)

        return created_objs

    @check_responsible_reason
    def create(self, **kwargs):
        history_kwargs = deepcopy(kwargs)
        try:
            del kwargs['reason']
        except KeyError:
            pass

        obj = self.model(**kwargs)
        self._for_write = True
        obj.save(
            reason=history_kwargs['reason'],
            force_insert=True,
            using=self.db
        )

        return obj

    @check_responsible_reason
    def get_or_create(self, defaults=None, **kwargs):
        get_kwargs = deepcopy(kwargs)
        try:
            del get_kwargs['reason']
        except KeyError:
            pass
        try:
            result = super(GenericUserToGroupQuerySet, self).get_or_create(defaults=defaults, **get_kwargs)
        except NoReasonSpecified:
            # in case there's no such record in db, create will raise NoReasonSpecified error
            # due to absence of reason field.
            # Here we explicitly create new record with such field.
            if defaults:
                kwargs.update(defaults)
            result = self.create(**kwargs)
        return (result, True) if not isinstance(result, tuple) else result


class OwnerToPermissionQuerySet(QuerySet):
    def without_obj_perms(self):
        return self.filter(
            object_id__isnull=True,
            content_type_id__isnull=True
        )

    @check_responsible_reason
    def delete(self, **kwargs):
        histories_to_create = list()

        objs_to_delete = self.values(*self.model().values_to_save_for_history().keys())
        HistoryOwnerToPermission = apps.get_model('protector', 'HistoryOwnerToPermission')

        for obj in objs_to_delete:
            obj.update({
                'reason': kwargs.get('reason'),
                'responsible': kwargs.get('responsible'),
                'change_type': HistoryOwnerToPermission.TYPE_REMOVE,
            })
            histories_to_create.append(HistoryOwnerToPermission(**obj))

        HistoryOwnerToPermission.objects.bulk_create(histories_to_create)

        return super(OwnerToPermissionQuerySet, self).delete()

    @check_responsible_reason
    def create(self, **kwargs):
        history_kwargs = deepcopy(kwargs)
        try:
            del kwargs['reason']
        except KeyError:
            pass

        obj = self.model(**kwargs)
        self._for_write = True
        obj.save(
            reason=history_kwargs['reason'],
            force_insert=True,
            using=self.db
        )

        return obj

    @check_responsible_reason
    def get_or_create(self, defaults=None, **kwargs):
        get_kwargs = deepcopy(kwargs)
        try:
            del get_kwargs['reason']
        except KeyError:
            pass
        try:
            result = super(OwnerToPermissionQuerySet, self).get_or_create(defaults=defaults, **get_kwargs)
        except NoReasonSpecified:
            # in case there's no such record in db, create will raise NoReasonSpecified error
            # due to absence of reason field.
            # Here we explicitly create new record with such field.
            if defaults:
                kwargs.update(defaults)
            result = self.create(**kwargs)
        return (result, True) if not isinstance(result, tuple) else result

    @check_responsible_reason
    def bulk_create(self, objs, batch_size=None, **kwargs):
        HistoryOwnerToPermission = apps.get_model('protector', 'HistoryOwnerToPermission')

        created_objs = super(OwnerToPermissionQuerySet, self).bulk_create(objs, batch_size=batch_size)

        hist_objs = deepcopy(objs)
        hist_objs_to_create = list()
        for obj in hist_objs:
            obj = obj.values_to_save_for_history()
            obj.update({
                'change_type': HistoryOwnerToPermission.TYPE_ADD,
                'reason': kwargs.get('reason'),
            })
            hist_objs_to_create.append(HistoryOwnerToPermission(**obj))

        HistoryOwnerToPermission.objects.bulk_create(hist_objs_to_create, batch_size=batch_size)

        return created_objs


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
            GenericUserToGroup.objects.bulk_create(links_to_create, reason=GENERIC_GROUP_UPDATE_REASON)

    def create(self, **kwargs):
        instance = super(GenericGroupQuerySet, self).create(**kwargs)
        instance._update_member_foreign_key()
        return instance
