from django.contrib import admin

try:
    from django.urls import path
    urlpatterns = (
        path('admin/', admin.site.urls),    
    )
except ImportError:
    from django.conf.urls import url, include
    urlpatterns = (
        url(r'^admin/', include(admin.site.urls)),    
    )
