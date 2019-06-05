# -*- coding: utf-8 -*-
class NoReasonSpecified(BaseException):
    def __init__(self, message=u'You should point the reason for this action'):
        super(NoReasonSpecified, self).__init__(message)


class ImproperInitiatorInstancePassed(BaseException):
    def __init__(self, message=u'Initiator should be an instance of User model'):
        super(ImproperInitiatorInstancePassed, self).__init__(message)
