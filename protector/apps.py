# -*- coding: utf-8 -*-

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class ProtectorConfig(AppConfig):
    name = 'protector'
    verbose_name = _("Protector")
