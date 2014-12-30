import os, sys
os.environ['DJANGO_SETTINGS_MODULE'] = 'application.settings'
test_dir = os.path.dirname(__file__)
sys.path.insert(0, test_dir + '/test_project')

from django.test.utils import get_runner
from django.conf import settings
import django


def runtests():
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=1, interactive=True)
    failures = test_runner.run_tests(['protector'])
    sys.exit(bool(failures))
