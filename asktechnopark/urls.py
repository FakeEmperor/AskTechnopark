"""
Definition of urls for asktechnopark.
"""

from datetime import datetime
from django.conf.urls import patterns, url, include
from blog.forms import BootstrapAuthenticationForm
from blog.urls import urlpatterns

# Uncomment the next lines to enable the admin:
# from django.conf.urls import include
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    (r'', include('blog.urls')),   
    (r'api', include('api.urls')),
    

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
