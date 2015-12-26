from datetime import datetime
from django.conf.urls import patterns, url
from blog.forms import BootstrapAuthenticationForm

urlpatterns = patterns('',
    # Examples:
    url(r'^$', 'blog.views.home', name='home'),
    url(r'^login/$',
        'django.contrib.auth.views.login',
        {
            'template_name': 'blog/login.html',
            'authentication_form': BootstrapAuthenticationForm,
            'extra_context':
            {
                'title':'Log in',
                'year':datetime.now().year,
            }
        },
        name='login'),
    url(r'^logout$',
        'django.contrib.auth.views.logout',
        {
            'next_page': '/',
        },
        name='logout'),
 )