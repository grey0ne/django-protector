from __future__ import unicode_literals

from past.builtins import basestring
from functools import wraps
from django.contrib.auth import get_user_model
from protector.exceptions import NoReasonSpecified, ImproperResponsibleInstancePassed


def check_responsible_reason(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        responsible = kwargs.get('responsible') or kwargs.get('responsible_id')
        reason = kwargs.get('reason') or (len(args) > 2 and args[2])
        if responsible is not None:
            if isinstance(responsible, int):
                raise ImproperResponsibleInstancePassed(
                    'If you meant to pass responsible user, please point the specific user model, not the id.'
                )
            if not isinstance(responsible, get_user_model()):
                raise ImproperResponsibleInstancePassed
        if not isinstance(reason, basestring) or not len(reason):
            raise NoReasonSpecified

        return func(*args, **kwargs)
    return wrapper
