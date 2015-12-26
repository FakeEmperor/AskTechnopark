import json
import enum
from django.http import HttpResponse


class APIResponse(object):
    API_RESULT_OK           = 0
    API_RESULT_UNDEFINED    = -1

    _success_overriden
    _success
    warnings
    errors
    code
    data

    def __init__(self, success = None, warnings = None, errors = None, code = None, data = None, result_code = None):
        self._success = success if success is not None else False

        self._success_overriden = success is not None
        self.data =         data if data is not None else {}
        self.errors =       errors if errors is not None else []
        self.warnings =     warnings if warnings is not None else []
        self.result_code =  result_code if result_code is not None else APIResponse.API_RESULT_UNDEFINED
    @property
    def success(self):
        return self._success;

    @success.setter
    def success(self, value):
        self._success_overriden = True
        self._success = value

    def __str__(self):
        if(not self._success_overriden):
            self._success = True
        s = json.dumps({"success":self._success, "warnings": self.warnings, "errors":errors, "code":self.result_code,"data":data})
        return s
     
    @classmethod
    def BuildError(cls, msg:str):
        ar = cls(success = False, errors = [msg], code = 1)
        return ar

    @staticmethod
    def AsResponse(resp, code = 200):
        response = HttpResponse(str.encode(resp.__str__()),code = code)
        return response