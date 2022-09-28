import os
import protector
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-protector',
    version=protector.__version__,
    packages=['protector'],
    include_package_data=True,
    license='MIT License',
    description='Django application for managing object level permissions and generic groups',
    url='https://github.com/grey0ne/django-protector',
    author='Sergey Lihobabin',
    author_email='greyone@greyone.ru',
    test_suite='runtests.runtests',
    install_requires=[
        'django-mptt>=0.8.6',
        'Django>=2.2',
        'future>=0.16.0'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
