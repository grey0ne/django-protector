# coding:utf-8
from protector.models import Restriction, OwnerToPermission, \
    GenericUserToGroup, GenericGlobalPerm
from django.contrib import admin
from django.contrib.contenttypes.admin import GenericTabularInline
from django.contrib.contenttypes.models import ContentType


class RestrictedAdminMixin(admin.ModelAdmin):

    def __init__(self, *args, **kwargs):
        super(RestrictedAdminMixin, self).__init__(*args, **kwargs)
        if not self.raw_id_fields:
            self.raw_id_fields = []
        self.raw_id_fields = list(self.raw_id_fields)
        if 'restriction_content_type' not in self.raw_id_fields:
            self.raw_id_fields.append('restriction_content_type')

    def get_fieldsets(self, request, obj=None):
        fieldsets = super(RestrictedAdminMixin, self).get_fieldsets(request, obj)
        restricted_fields = ('restriction_content_type', 'restriction_id')
        for fieldset in fieldsets:
            fieldset[1]['fields'] = [field for field in fieldset[1]['fields'] if field not in restricted_fields]
        return fieldsets + [
            (
                u'Restriction options', {'fields': (restricted_fields,)}
            ),
        ]


class UserGroupInline(GenericTabularInline):
    model = GenericUserToGroup
    verbose_name = 'User'
    verbose_name_plural = 'Users'
    ct_field = 'group_content_type'
    ct_fk_field = 'group_id'
    raw_id_fields = ('user', 'responsible', 'content_type')
    list_select_related = ('user', )
    extra = 1
    max_num = 10


class GenericGroupAdminMixin(admin.ModelAdmin):
    def __init__(self, *args, **kwargs):
        super(GenericGroupAdminMixin, self).__init__(*args, **kwargs)
        if not self.inlines:
            self.inlines = []
        if UserGroupInline not in self.inlines:
            self.inlines = list(self.inlines)
            self.inlines.append(UserGroupInline)
            self.inlines.append(PermissionOwnerInline)


class OwnerToPermissionAdmin(admin.ModelAdmin):
    search_fields = ('permission__name', )
    list_filter = ('owner_content_type', )
    list_display = (
        'owner_content_type', 'owner_object_id', 'object_id',
        'content_type', 'date_issued', 'permission'
    )
    list_select_related = ('owner_content_type', 'content_type', 'permission')
    date_hierarchy = 'date_issued'
    raw_id_fields = ('owner_content_type', 'content_type', 'permission', 'responsible')


class PermissionObjectInline(GenericTabularInline):
    fields = ('owner_object_id', 'owner_content_type', 'permission', 'roles', 'responsible')
    raw_id_fields = ('responsible', 'owner_content_type', 'permission')
    readonly_fields = ('date_issued', )
    verbose_name = 'Permission on this object'
    verbose_name_plural = 'Permissions on this object'
    model = OwnerToPermission
    ct_field = 'content_type'
    ct_fk_field = 'object_id'
    extra = 1


class PermissionOwnerInline(GenericTabularInline):
    fields = ('object_id', 'content_type', 'permission', 'roles', 'responsible')
    raw_id_fields = ('responsible', 'content_type', 'permission')
    verbose_name = 'Permission'
    verbose_name_plural = 'Permissions'
    readonly_fields = ('date_issued', )
    model = OwnerToPermission
    ct_field = 'owner_content_type'
    ct_fk_field = 'owner_object_id'
    extra = 1


class GenericUserToGroupAdmin(admin.ModelAdmin):
    search_fields = ('user__username', )
    list_display = ('group_content_type', 'group_id', 'user', 'roles', 'date_joined')
    list_filter = ('group_content_type', )
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
admin.site.register(ContentType)
