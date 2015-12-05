from django import forms
from protector.models import OwnerToPermission
from protector.helpers import get_permission_id_by_name


class PermissionModeratorForm(forms.ModelForm):

    def save(self, commit=True):
        instance = super(PermissionModeratorForm, self).save(commit=False)
        instance.permission_id = get_permission_id_by_name(
            'protector.{0}'.format(OwnerToPermission.ADD_PERMISSION)
        )
        if commit:
            instance.save()
        return instance

    class Meta:
        exclude = ('permission', )
        model = OwnerToPermission
