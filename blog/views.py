"""
Definition of views.
File: blog.views

"""
from django.core.urlresolvers import reverse
from django.shortcuts import render, redirect, resolve_url
from django.http import HttpRequest
from django.template import RequestContext
from datetime import datetime
import django.http
import django.core.exceptions
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as _login
from blog.forms import BootstrapAuthenticationForm

# internal
import penguin.utils.security
import api.user.auth

def home(request):
    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'index.html',
        context_instance=RequestContext(request,
        {
            'title': 'Home Page',
            'page_title': 'Лента',
            'year': datetime.now().year,
        })
    )


def forgot(request):
    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'forgot.html',
        context_instance=RequestContext(request,
        {
            'title': 'Home Page',
            'page_title': 'Лента',
            'year': datetime.now().year,
        })
    )


@never_cache
@ensure_csrf_cookie
def login(request):
    assert isinstance(request, HttpRequest)
    not_auth = True
    username = None
    error = None
    if request.method == 'POST':
        # this is login without AJAX
        # override password
        passw = request.POST.get('password')
        if passw:
            # TODO: MAKE AJAX AUTHORIZATION! FFFUUU!!!
            passw = penguin.utils.security.get_hash(passw)
        f = BootstrapAuthenticationForm(request,
                                        data={'username': request.POST.get("username"),'password':passw})
        if f.is_valid():
            # go fuck myself
            api.user.auth.login(request, f.get_user())
            not_auth = False
    else:
        # this is rendering page
        f = BootstrapAuthenticationForm(request)
    # render the page
    if not_auth:
        return render(request, 'login.html',
                      context_instance=RequestContext(request,
                        {
                            'form': f,
                            'title': 'Log in Page',
                            'page_title': 'Log in',
                            'page_settings': {
                              'sidebar_disabled': True
                            },
                            'year': datetime.now().year,
                        })
                      )
    else:
        # forward or not?
        next = request.GET.get('next')
        return redirect(next if next is not None else reverse('home'))

def register(request):
    return django.http.HttpResponseNotFound(request)

