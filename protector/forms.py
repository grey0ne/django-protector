from django import forms
from protector.models import OwnerToPermission

class OwnerPermissionForm(forms.ModelForm):
    
    class Meta:
        model = OwnerToPermission
