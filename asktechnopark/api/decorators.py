import django
import random
import datetime
import django.core.signing
from django.http import HttpRequest
from django.http import HttpResponse
import django.http
from django.template import RequestContext, loader
from django.core.signing import BadSignature, SignatureExpired

from asktechnopark.api.response import APIResponse
import blog.models
"""
This decorator checks obligatory parameters for any api call:
uid - user id (validates)
sid - session id (validates)
hash - hash from method string + salt (in cookie)
"""
def api_parameters_check_or_403(function):
    def wrapper(request):
        #check parameters
        assert isinstance(request, HttpRequest)
        uid = request.GET.get("uid")
        sid = request.GET.get("sid")
        hash    =   request.GET.get("hash")


        if uid is None or session_id is None or hash is None:
            ar = APIResponse.BuildError("One or more obligatory params aren't set")
            return APIResponse.AsResponse(ar, 403)
        #check existence
        user = None
        session = None
        try:
            user = blog.models.User.objects.get(pk = uid)
            assert isinstance(user, blog.models.User)
            session = user.session_set.get(pk = sid)
            assert isinstance(session, blog.models.Session)
            if( session.GetHashFromPath(request.get_full_path()) != hash):
                ar = APIResponse.BuildError("API Call hash inconsistent")
                return APIResponse.AsResponse(ar, 403)
            
            request.user = user
            request.db_session = session 
            
        except :
            ar = APIResponse.BuildError("One or more obligatory params aren't set")
            return APIResponse.AsResponse(ar, 403)
        return function(request)
         # the () after "original_function" causes original_function to be called
    return wrapper


"""
Ensures, that cookie session is set before control is passed onto
the wrapped method.
"""
def ensure_session(function):
    def wrapper(request):
        assert isinstance(request, HttpRequest)
