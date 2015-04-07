# coding:utf-8
from protector.models import Restriction, OwnerToPermission, \
    GenericUserToGroup, GenericGlobalPerm
from django.contrib import admin


class OwnerToPermissionAdmin(admin.ModelAdmin):
    list_filter = ('owner_content_type', )
    list_display = ('owner_content_type', 'owner_object_id', 'date_issued', 'permission')
    date_hierarchy = 'date_issued'
    search_fields = ('permission__name', )
    raw_id_fields = ('owner_content_type', 'content_type', 'permission', 'responsible')


class GenericUserToGroupAdmin(admin.ModelAdmin):
    search_fields = ['user__username', ]
    list_display = ['group_content_type', 'group_id', 'user', 'roles', 'date_joined']
    date_hierarchy = 'date_joined'
    raw_id_fields = ('user', 'responsible', 'group_content_type')


class GenericGlobalPermAdmin(admin.ModelAdmin):
    raw_id_fields = ('permission', 'content_type')
    list_display = ('permission', 'content_type', 'roles')


class RestrictionAdmin(admin.ModelAdmin):
    list_display = ('parent', 'object_id', 'content_type')
    raw_id_fields = ('parent', )
    list_select_related = ('parent', 'content_type')


admin.site.register(GenericGlobalPerm, GenericGlobalPermAdmin)
admin.site.register(GenericUserToGroup, GenericUserToGroupAdmin)
admin.site.register(OwnerToPermission, OwnerToPermissionAdmin)
admin.site.register(Restriction, RestrictionAdmin)
