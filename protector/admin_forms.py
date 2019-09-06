from past.builtins import basestring
from django import forms
from django.core.exceptions import ValidationError
from protector.models import OwnerToPermission, GenericUserToGroup
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


class HistoryDependantModelsForm(forms.ModelForm):
    reason = forms.CharField(required=True)

    def save(self, commit=True):
        reason = self.cleaned_data.get('reason')
        if not reason or not isinstance(reason, basestring):
            raise ValidationError('You should point the reason for this action')
        instance = super(HistoryDependantModelsForm, self).save(commit=False)
        if commit:
            instance.save(reason=reason)
        return instance

    class Meta:
        fields = '__all__'


class OwnerToPermissionForm(HistoryDependantModelsForm):
    class Meta(HistoryDependantModelsForm.Meta):
        model = OwnerToPermission


class GenericUserToGroupForm(HistoryDependantModelsForm):
    class Meta(HistoryDependantModelsForm.Meta):
        model = GenericUserToGroup
