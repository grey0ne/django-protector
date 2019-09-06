
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

import sys
sys.path.insert(1, BASE_DIR + '/..')

SECRET_KEY = '($7wfk^1hd5+i-2j1k^h$v^-r-7r$47f@2-9&_%5tlk^9wwfi6'

DEBUG = True

TEMPLATE_DEBUG = False

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ]
        },
    },
]

ALLOWED_HOSTS = ['*', ]

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.messages',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.staticfiles',
    'protector',
    'test_app'
)

MIDDLEWARE = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'application.urls'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

STATIC_URL = '/static/'

AUTH_USER_MODEL = 'test_app.TestUser'
PROTECTOR_GENERIC_GROUP = 'test_app.TestGroup'

AUTHENTICATION_BACKENDS = (
    'application.backends.TestBackend',
    'django.contrib.auth.backends.ModelBackend',
)
