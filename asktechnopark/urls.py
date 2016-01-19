"""
Definition of urls for asktechnopark.
"""

from datetime import datetime
from django.conf.urls import patterns, url, include
from blog.forms import BootstrapAuthenticationForm
import django.contrib.auth.views
# Uncomment the next lines to enable the admin:
# from django.conf.urls import include
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = [
    url(r'^', include('blog.urls', )),

    url(r'^api/', include('api.urls', )),
    

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
]
