from django.contrib.auth.models import Permission
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from protector.query import Query
from protector.models import get_permission_owners_query, OwnerToPermission, \
    NULL_OWNER_TO_PERMISSION_OBJECT_ID, NULL_OWNER_TO_PERMISSION_CTYPE_ID, \
    _generate_filter_condition

condition_template = " op.object_id = {null_id!s} AND op.content_type_id = {null_ctype!s} "
NULL_OBJECT_CONDITION = condition_template.format(
    null_id=NULL_OWNER_TO_PERMISSION_OBJECT_ID,
    null_ctype=NULL_OWNER_TO_PERMISSION_CTYPE_ID
)


def get_all_permission_owners(permission, include_superuser=False, include_groups=True, obj=None):
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
    perm_query.fields.append("IFNULL(op.permission_id, gl.permission_id) as perm_id")
    perm_query.fields.append("gl.permission_id AS gl_perm_id")
    perm_query.conditions.append("gug.user_id = {user_id!s}".format(user_id=user.id))
    query = Query(tables=[
        """
            {permission_table!s} perm_table LEFT JOIN {content_type_table!s} ctype_table ON
            perm_table.content_type_id=ctype_table.id INNER JOIN (
                {permission_owners_query!s}
            ) perm_query ON perm_query.perm_id = perm_table.id
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
    qs = OwnerToPermission.objects.filter(
        content_type=ContentType.objects.get_for_model(content_object._meta.model),
        object_id=content_object.pk,
        owner_content_type=owner_content_type,
        permission=permission
    )
    return owner_content_type.model_class().objects.filter(
        id__in=qs.values_list('owner_object_id', flat=True)
    )


def _get_permissions_query(obj=None):
    query = Query(
        tables=[get_permission_owners_query()]
    )
    if obj is None:
        query.conditions.append(NULL_OBJECT_CONDITION)
    else:
        query.params.update({
            'object_pk': obj.pk, 'ctype_pk': ContentType.objects.get_for_model(obj).pk,
            'null_object_condition': NULL_OBJECT_CONDITION,
            'null_object_id': NULL_OWNER_TO_PERMISSION_OBJECT_ID
        })
        query.conditions.append(
            """
                ({null_object_condition!s})
                OR (op.content_type_id = {ctype_pk!s} AND
                    (op.object_id = {object_pk!s} OR op.object_id = {null_object_id!s})
                )
                OR (
                    gl.content_type_id = gug.group_content_type_id AND
                    gug.group_id = {object_pk!s} AND gug.group_content_type_id = {ctype_pk!s}
                )
            """
        )
    return query


def generate_obj_list_query(object_list):
    select_list = ["SELECT %s as ctype_id, %s as object_id " % (obj[0], obj[1]) for obj in object_list]
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
