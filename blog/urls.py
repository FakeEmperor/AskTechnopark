from datetime import datetime
from django.conf.urls import patterns, url
from blog.forms import BootstrapAuthenticationForm
import blog.views
import django.contrib.auth.views

urlpatterns = [
    # Examples:
    url(r'^$', blog.views.home, name='home'),
    url(r'^register/$', blog.views.register,
        name='register'),
    url(r'^login/$', blog.views.login, name='login'),
    url(r'^logout$',
        'django.contrib.auth.views.logout',
        {
            'next_page': 'home',
        },
        name='logout'),
    url(r'^forgot/$', blog.views.forgot, name='forgot_password')
]