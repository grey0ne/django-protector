from past.builtins import basestring
from functools import wraps
from django.contrib.auth.models import Permission
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.db import connection
from django.apps import apps
from protector.query import Query
from protector.internals import (
    get_permission_owners_query, _generate_filter_condition,
    _get_permission_filter, VIEW_RESTRICTED_OBJECTS, _get_permissions_query,
)

from protector.exceptions import NoReasonSpecified, ImproperResponsibleInstancePassed


_view_perm = None


def check_responsible_reason(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        responsible = kwargs.get('responsible')
        reason = kwargs.get('reason') or (len(args) > 2 and args[2])
        if responsible is not None and not isinstance(responsible, get_user_model()):
            raise ImproperResponsibleInstancePassed
        if not isinstance(reason, basestring) or not len(reason):
            raise NoReasonSpecified

        return func(*args, **kwargs)
    return wrapper


def get_all_permission_owners(permission, include_superuser=False, obj=None):
    query = _get_permissions_query(obj)
    query.fields.append("gug.user_id AS id")
    query.conditions.append("op.permission_id = {perm_id!s}")
    query.params.update({'perm_id': permission.id})
    table_name = get_user_model()._meta.db_table
    condition = "{table_name!s}.id IN ({subquery!s})"
    if include_superuser:
        condition += " OR {table_name!s}.is_superuser"
    condition = condition.format(
        table_name=table_name, subquery=query.get_raw_query()
    )
    return get_user_model().objects.extra(where=[condition])


def get_all_user_permissions(user, obj=None):
    perm_query = _get_permissions_query(obj)
    perm_query.fields.append("op.permission_id as perm_id")
    perm_query.fields.append("gl.permission_id AS gl_perm_id")
    perm_query.conditions.append("gug.user_id = {user_id!s}".format(user_id=user.id))
    query = Query(tables=[
        """
            {permission_table!s} perm_table LEFT JOIN {content_type_table!s} ctype_table ON
            perm_table.content_type_id=ctype_table.id INNER JOIN (
                {permission_owners_query!s}
            ) perm_query ON perm_query.perm_id = perm_table.id
                OR perm_query.gl_perm_id = perm_table.id
        """.format(
            permission_table=Permission._meta.db_table,
            content_type_table=ContentType._meta.db_table,
            permission_owners_query=perm_query.get_raw_query(),
        )
    ])
    query.fields.append("perm_table.id as id")
    query.fields.append("perm_table.codename as codename")
    query.fields.append("ctype_table.app_label as app_label")
    perms = Permission.objects.raw(query.get_raw_query())
    return set("{app}.{codename}".format(app=p.app_label, codename=p.codename) for p in perms)


def get_permission_owners_of_type_for_object(permission, owner_content_type, content_object):
    OwnerToPermission = apps.get_model('protector', 'OwnerToPermission')
    qs = OwnerToPermission.objects.filter(
        content_type=ContentType.objects.get_for_model(content_object._meta.model),
        object_id=content_object.pk,
        owner_content_type=owner_content_type,
        permission=permission
    )
    return owner_content_type.model_class().objects.filter(
        id__in=qs.values_list('owner_object_id', flat=True)
    )


def generate_obj_list_query(object_list):
    select_list = [
        "SELECT %s as ctype_id, %s as object_id " % (obj[0], obj[1]) for obj in object_list
    ]
    return " UNION ALL ".join(select_list)


def filter_object_id_list(object_list, user_id, permission_id):
    # object_list list is a list of tuples (ctype_id, object_id)
    query = """
        SELECT ctype_id, object_id FROM ({ids_query}) AS ids
        WHERE EXISTS (SELECT op.id FROM {permission_owners} WHERE {filter_condition})
    """
    query = query.format(
        ids_query=generate_obj_list_query(object_list),
        permission_owners=get_permission_owners_query(),
        filter_condition=_generate_filter_condition(
            user_id, permission_id, 'ids.ctype_id', 'ids.object_id'
        )
    )
    cursor = connection.cursor()
    cursor.execute(query)
    return [(row[0], row[1]) for row in cursor.fetchall()]


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


def filter_queryset_by_permission(qset, user, permission):
    perm_id = get_permission_id_by_name(permission)
    if user.has_perm(permission):
        return qset.all()
    if user.id is None or perm_id is None:
        return qset.none()
    condition = _get_permission_filter(qset, user.id, perm_id)
    result = qset.extra(where=[condition])
    return result


def get_view_permission():
    codename = VIEW_RESTRICTED_OBJECTS
    global _view_perm
    OwnerToPermission = apps.get_model('protector', 'OwnerToPermission')
    if _view_perm is None:
        ctype = ContentType.objects.get_for_model(OwnerToPermission)
        _view_perm = Permission.objects.get(
            codename=codename, content_type=ctype
        )
    return _view_perm


def is_user_having_perm_on_any_object(user, permission):
    if user.is_superuser:
        return True
    perm_id = get_permission_id_by_name(permission)
    if perm_id is None:
        return False
    query = """
        SELECT op.id FROM {permission_owners}
        WHERE op.permission_id = {permission_id} AND gug.user_id = {user_id}
        LIMIT 1;
    """
    query = query.format(
        permission_owners=get_permission_owners_query(),
        permission_id=perm_id,
        user_id=user.id
    )
    cursor = connection.cursor()
    cursor.execute(query)
    return len(cursor.fetchall()) > 0


def check_single_permission(user, permission, obj=None):
    if user.is_superuser:
        return True
    if obj is not None and obj.id is not None:
        ctype_id = ContentType.objects.get_for_model(obj).id
        obj_id = obj.id
    else:
        ctype_id = None
        obj_id = None
    perm_id = get_permission_id_by_name(permission)
    if perm_id is None:
        return False
    query = "SELECT op.id FROM {permission_owners} WHERE {filter_condition} LIMIT 1"
    query = query.format(
        permission_owners=get_permission_owners_query(),
        filter_condition=_generate_filter_condition(
            user.id, perm_id, ctype_id, obj_id
        )
    )
    cursor = connection.cursor()
    cursor.execute(query)
    return len(cursor.fetchall()) > 0
