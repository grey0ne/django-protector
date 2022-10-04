# coding:utf-8
from protector.models import (
    Restriction,
    OwnerToPermission,
    GenericUserToGroup,
    GenericGlobalPerm,
    PermissionInfo,
)
from protector.reserved_reasons import ADMIN_PANEL_DELETE_REASON
from protector.admin_forms import (
    PermissionModeratorForm,
    GenericUserToGroupForm,
    OwnerToPermissionForm,
)
from django.contrib import admin
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.admin import GenericTabularInline
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _


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
            fieldset[1]['fields'] = [
                field for field in fieldset[1]['fields'] if field not in restricted_fields
            ]
        return fieldsets + [
            (
                _('Restriction options'), {'fields': (restricted_fields,)}
            ),
        ]


class UserGroupInline(GenericTabularInline):
    model = GenericUserToGroup
    verbose_name = _('User')
    verbose_name_plural = _('Users')
    ct_field = 'group_content_type'
    ct_fk_field = 'group_id'
    raw_id_fields = ('user', 'responsible', 'group_content_type')
    list_select_related = ('user', )
    extra = 1
    max_num = 10


class GenericGroupAdminMixin(admin.ModelAdmin):

    save_on_top = True

    def __init__(self, *args, **kwargs):
        super(GenericGroupAdminMixin, self).__init__(*args, **kwargs)
        if not self.inlines:
            self.inlines = []
        if UserGroupInline not in self.inlines:
            self.inlines = list(self.inlines)
            self.inlines.append(UserGroupInline)
            self.inlines.append(PermissionOwnerInline)


class OwnerToPermissionAdmin(admin.ModelAdmin):
    save_as = True
    form = OwnerToPermissionForm
    search_fields = ('permission__name', )
    list_filter = ('owner_content_type', )
    list_display = (
        'owner_content_type', 'owner_object_id', 'object_id',
        'content_type', 'date_issued', 'permission'
    )
    list_select_related = ('owner_content_type', 'content_type', 'permission')
    date_hierarchy = 'date_issued'
    raw_id_fields = ('owner_content_type', 'content_type', 'permission', 'responsible')
    actions = ['delete_qs']

    def get_actions(self, request):
        actions = super(OwnerToPermissionAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def save_model(self, request, obj, form, change):
        reason = form.cleaned_data.get('reason')
        obj.save(reason=reason)

    def delete_qs(self, request, queryset):
        queryset.delete(reason=ADMIN_PANEL_DELETE_REASON(request.user))
    delete_qs.short_description = u'Delete selected owner to permission records'

    def delete_model(self, request, obj):
        obj.delete(reason=ADMIN_PANEL_DELETE_REASON(request.user))


class PermissionObjectInline(GenericTabularInline):
    fields = (
        'owner_object_id', 'owner_content_type',
        'permission', 'roles', 'responsible'
    )
    raw_id_fields = ('responsible', 'owner_content_type', 'permission')
    readonly_fields = ('date_issued', )
    verbose_name = _('Permission on this object')
    verbose_name_plural = _('Permissions on this object')
    model = OwnerToPermission
    ct_field = 'content_type'
    ct_fk_field = 'object_id'
    extra = 1


class PermissionOwnerInline(GenericTabularInline):
    fields = (
        'object_id', 'content_type', 'permission',
        'roles', 'responsible'
    )
    raw_id_fields = ('responsible', 'content_type', 'permission')
    verbose_name = _('Permission')
    verbose_name_plural = _('Permissions')
    readonly_fields = ('date_issued', )
    model = OwnerToPermission
    ct_field = 'owner_content_type'
    ct_fk_field = 'owner_object_id'
    extra = 1


class GenericUserToGroupAdmin(admin.ModelAdmin):
    save_as = True
    search_fields = ('user__username', )
    form = GenericUserToGroupForm
    list_display = ('group_content_type', 'group_id', 'user', 'roles', 'date_joined')
    list_filter = ('group_content_type', )
    date_hierarchy = 'date_joined'
    raw_id_fields = ('user', 'responsible', 'group_content_type')
    actions = ['delete_qs']

    def get_actions(self, request):
        actions = super(GenericUserToGroupAdmin, self).get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    def save_model(self, request, obj, form, change):
        reason = form.cleaned_data.get('reason')
        obj.save(reason=reason)

    def delete_qs(self, request, queryset):
        queryset.delete(reason=ADMIN_PANEL_DELETE_REASON(request.user))
    delete_qs.short_description = u'Delete selected user to group records'

    def delete_model(self, request, obj):
        obj.delete(reason=ADMIN_PANEL_DELETE_REASON(request.user))


class GenericGlobalPermAdmin(admin.ModelAdmin):
    save_as = True
    raw_id_fields = ('permission', 'content_type')
    list_display = ('permission', 'content_type', 'roles')


class RestrictionAdmin(admin.ModelAdmin):
    list_display = ('parent', 'object_id', 'content_type')
    raw_id_fields = ('parent', )
    list_select_related = ('parent', 'content_type')


class ContentTypeAdmin(admin.ModelAdmin):
    list_filter = ('app_label', )
    list_display = ('app_label', 'model', 'name')
    search_fields = ('app_label', 'model')


class OwnerToPermissionInline(admin.TabularInline):
    model = OwnerToPermission
    fields = (
        ('content_type', 'object_id'),
        ('owner_content_type', 'owner_object_id'),
        'permission', 'roles', 'responsible'
    )
    raw_id_fields = ('responsible', 'content_type', 'owner_content_type', 'permission')
    verbose_name = _('Permission owner')
    verbose_name_plural = _('Permission owners')
    extra = 1


class PermissionModeratorInline(GenericTabularInline):
    model = OwnerToPermission
    form = PermissionModeratorForm
    raw_id_fields = ('owner_content_type', 'responsible')
    verbose_name = _('Permission moderator')
    verbose_name_plural = _('Permission moderators')
    ct_field = 'content_type'
    ct_fk_field = 'object_id'
    extra = 1

    def get_queryset(self, request):
        qset = super(PermissionModeratorInline, self).get_queryset(request)
        qset.filter(
            permission__codename=OwnerToPermission.ADD_PERMISSION,
            permission__content_type__app_label='protector'
        )


class PermissionInfoInline(admin.StackedInline):
    model = PermissionInfo
    max_num = 1
    can_delete = False


class PermissionAdmin(admin.ModelAdmin):
    list_filter = ('content_type', )
    list_display = ('name', 'codename', 'content_type', )
    raw_id_fields = ('content_type', )
    search_fields = ('name', 'codename', )

    inlines = [
        OwnerToPermissionInline, PermissionModeratorInline,
        PermissionInfoInline
    ]


admin.site.register(GenericGlobalPerm, GenericGlobalPermAdmin)
admin.site.register(GenericUserToGroup, GenericUserToGroupAdmin)
admin.site.register(OwnerToPermission, OwnerToPermissionAdmin)
admin.site.register(Restriction, RestrictionAdmin)
admin.site.register(Permission, PermissionAdmin)

if ContentType not in admin.site._registry:
    admin.site.register(ContentType, ContentTypeAdmin)
