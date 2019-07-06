# -*- coding: utf-8 -*-
from __future__ import unicode_literals


class NoReasonSpecified(BaseException):
    def __init__(self, message='You should point the reason for this action'):
        super(NoReasonSpecified, self).__init__(message)


class ImproperResponsibleInstancePassed(BaseException):
    def __init__(self, message='Responsible should be an instance of User model'):
        super(ImproperResponsibleInstancePassed, self).__init__(message)
