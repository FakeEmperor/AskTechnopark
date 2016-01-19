# vendor
from django.shortcuts import render
from django.http import HttpRequest
from django.template import RequestContext
import django.http.response
from datetime import datetime
import blog.models
import django.db.models
from django.views.decorators.csrf import ensure_csrf_cookie
import django.views.csrf
import django.conf
# internal
import api
from api.common import APIResult, BatchedAPIResult, APIResultCode
from api.response import APIResponse
import blog.models as models
import api.mailing
import api.models

import blog.models
from api.decorators import APIParameter, APIParser,\
    api_parameters_check_or_gtfo, api_post_params_enable, api_batch_enable

@ensure_csrf_cookie
@api_post_params_enable(True, ('text', 'title'), True, True)
@api_parameters_check_or_gtfo(False, True, True, True, (
    APIParameter('text'),
    APIParameter('title'),
    APIParameter('type', APIParser.SELECT_CHOICE, choices={
        str(blog.models.PostType.ANSWER._name_).lower(): blog.models.PostType.ANSWER,
        str(blog.models.PostType.QUESTION._name_).lower(): blog.models.PostType.QUESTION
    }, key_name='type'),
    APIParameter('picid', APIParser.TO_INT, obligatory=False, key_name='picid', default=0),
))
# TODO: Enable picture support
def create(request, api_params):
    ar = APIResult()
    post = blog.models.Post.CreatePost(api_params['type'], api_params['user'],
                                       api_params['title'], api_params['text'],
                                       api_params['picid'], )
    ar.data = {'url': post.url, 'id': post.pk}
    ar.success = True
    return APIResponse.AsResponse(ar)

@ensure_csrf_cookie
@api_parameters_check_or_gtfo(False, False, False, False, (
    APIParameter('id', APIParser.TO_INT, key_name='id', obligatory=False),
    APIParameter('url', obligatory=False)
))
@api_batch_enable()
def view(request, api_params):
    if not api_params.get('batch_enabled'):
        id =  api_params['id']
        url = api_params['url']
        code = 200
        if not id and not url:
            ar = APIResult.BuildError("Set at least one of parameters: id, url", APIResultCode.ARC_OPT_OBLIGATORY_NOT_SET)
            code = APIResponse.STATUS_CODES[APIResultCode.ARC_OPT_OBLIGATORY_NOT_SET]
        else:
            try:
                # TODO: maybe there is a better way to do it
                if id:
                    if url:
                        post = blog.models.Post.objects.get(pk=id, url=url)
                    else:
                        post = blog.models.Post.objects.get(pk=id)
                else:
                    post = blog.models.Post.objects.get(url=url)
                ar = APIResult(True, data=post.dump())
            except blog.models.Post.DoesNotExist:
                ar = APIResult.BuildError("Post not found", APIResultCode.ARC_DB_NOT_FOUND_OBJECT)
                code = APIResponse.STATUS_CODES[APIResultCode.ARC_DB_NOT_FOUND_OBJECT]
        return APIResponse.AsResponse(ar, code)
    else:
        raise NotImplementedError("Batched is not yer implemented")