from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.conf import settings
from django.contrib.auth import get_user_model


ADD_PERMISSION_PERMISSION = 'add_permission'
VIEW_RESTRICTED_OBJECTS = 'view_restricted_objects'

VIEW_PERMISSION_NAME = 'protector.{0}'.format(VIEW_RESTRICTED_OBJECTS)


#  Need this to avoid null values in OwnerToPermission table
NULL_OWNER_TO_PERMISSION_OBJECT_ID = 0
NULL_OWNER_TO_PERMISSION_CTYPE_ID = 1  # That is ContentType ctype id

DEFAULT_ROLE = 1


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
    OwnerToPermission = apps.get_model('protector', 'OwnerToPermission')
    GenericUserToGroup = apps.get_model('protector', 'GenericUserToGroup')
    GenericGlobalPerm = apps.get_model('protector', 'GenericGlobalPerm')
    return owners_query.format(
        owner_table_name=OwnerToPermission._meta.db_table,
        group_table_name=GenericUserToGroup._meta.db_table,
        global_table_name=GenericGlobalPerm._meta.db_table,
        null_owner_id=NULL_OWNER_TO_PERMISSION_OBJECT_ID
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


def get_default_group_ctype():
    return ContentType.objects.get_by_natural_key(
        *settings.PROTECTOR_GENERIC_GROUP.lower().split('.')
    )


def get_user_ctype():
    return ContentType.objects.get_for_model(get_user_model())
