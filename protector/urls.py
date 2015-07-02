from django.conf.urls import url, patterns
from protector.views import AddPermissionView

urlpatterns = patterns(
    'protector.views',
    url(
        r'permission/(?P<permission_id>\d+)/add_to_object/(?P<content_type_id>\d+)/(?P<object_id>\d+)/$',
        AddPermissionView.as_view(), name='add_permission'
    )
)
