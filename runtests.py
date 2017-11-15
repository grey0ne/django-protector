import os
import sys
os.environ['DJANGO_SETTINGS_MODULE'] = 'application.settings'
test_dir = os.path.dirname(__file__)
sys.path.insert(0, test_dir + '/test_project')

from django.test.utils import get_runner
from django.conf import settings
import django


def runtests():
    django.setup()
    test_runner = get_runner(settings)(verbosity=2, interactive=True)
    failures = test_runner.run_tests(['protector', 'test_app'])
    sys.exit(bool(failures))
