"""
file: api.user.views 

"""

from django.shortcuts import render
from django.http import HttpRequest
from django.template import RequestContext
import django.http.response
from datetime import datetime
import blog.models
import django.db.models
import asktechnopark.api


class CustomAuthBackend(object):
    """
    This is custom authentication backend.
    Authenticate against the webservices call.

    The method below would override authenticate() of django.contrib.auth    
    """
    def authenticate_password(self, username:str=None, password:str=None):
        users = blog.models.User.objects
        assert isinstance(users, django.db.models.QuerySet)
        try:
            user = users.get(username=username)
            assert isinstance(user, blog.models.User)
            if( user.GetPwdHash(password) == user.password):
                return user
        except blog.models.User.DoesNotExist:
            pass
        return None

    def authenticate_token(self,token=None):
        return None

    def authenticate(self, token=None, username=None, password=None):
        if token is not None:
             return self.authenticate_token(token)
        else:
             return self.authenticate_password(username, password)


    def get_user(self, user_id):
        users = blog.models.User.objects
        assert isinstance(users, django.db.models.QuerySet)
        try:
            user = users.get(pk=user_id)
            assert isinstance(user, blog.models.User)
            return user
        except blog.models.User.DoesNotExist:
            pass
        return None

@asktechnopark.api.decorators.api_parameters_check_or_403
def login(request):
    assert isinstance(request, HttpRequest)

    return django.http.HttpResponse("lol")



from django.contrib.auth import authenticate

class AuthMiddleWare(object):
    def process_request(self, request):
        assert isinstance(request, HttpRequest)
        if request.path != '/favicon.ico':   
            if request.method == 'POST' and request.POST.has_key('username' ) and request.POST.has_key('password'):                     
                authenticate(username = request.POST.get('username'),password = request.POST.get('password'))
            elif '' in request.COOKIES:                     
                authenticate(token = request.COOKIES.get('SPRING_SECURITY_REMEMBER_ME_COOKIE'))

        return None