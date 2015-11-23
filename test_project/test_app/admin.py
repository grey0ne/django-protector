from django.contrib import admin
from test_app.models import TestUser, TestGroup
from protector.admin import PermissionObjectInline, PermissionOwnerInline, RestrictedAdminMixin


class TestUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email')
    inlines = (
        PermissionOwnerInline, 
    )


class TestGroupAdmin(RestrictedAdminMixin):
    list_display = ('name', )
    inlines = (
        PermissionOwnerInline, 
        PermissionObjectInline
    )


admin.site.register(TestUser, TestUserAdmin)
admin.site.register(TestGroup, TestGroupAdmin)
