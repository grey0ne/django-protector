from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.http import HttpResponse, Http404, HttpResponseForbidden, HttpResponseBadRequest
from django.core.exceptions import DoesNotExist
from django.shortcuts import render_to_response
from django.views.generic import View
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.template import RequestContext
from protector.models import ADD_PERMISSION_NAME
from protector.forms import UserChooseForm


class AddPermissionView(View):
    FORM_CLASS = UserChooseForm
    FORM_TEMPLATE = 'protector/user_choose_form.html'

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        if request.method not in ['POST', 'GET']:
            return HttpResponse(status_code=405, content='POST or GET required')
        self.object_id = kwargs.get('object_id')
        self.content_type_id = kwargs.get('content_type_id')
        self.instance = None
        try:
            self.permission = Permission.objects.get(id=kwargs.get('permission_id'))
        except Permission.DoesNotExist:
            raise Http404('permission not found')
        if self.object_id is not None or self.content_type_id is not None:
            try:
                ctype = ContentType.objects.get_for_id(self.content_type_id)
                self.instance = ctype.get_object_for_this_type(pk=self.object_id)
            except DoesNotExist:
                raise Http404('object not found')
        if not self.check_permissions():
            return self.not_allowed()
        return super(AddPermissionView, self).dispatch(request, *args, **kwargs)

    def check_permissions(self):
        return self.request.user.has_perm(ADD_PERMISSION_NAME, self.permission)

    def not_allowed(self):
        return HttpResponseForbidden('action not allowed')

    def post(self, request, *args, **kwargs):
        self.form = self.FORM_CLASS(request.POST)
        if self.form.is_valid():
            for user in self.form.cleaned_data['users']:
                user.permissions.add(self.permission, obj=self.instance)
        else:
            return HttpResponseBadRequest('invalid form data')

    def get(self, request, *args, **kwargs):
        self.form = self.FORM_CLASS()
        context = {'form': self.form}
        return render_to_response(
            self.FORM_TEMPLATE, context, context_instance=RequestContext(request)
        )
