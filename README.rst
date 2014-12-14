=====
Protector
=====

Protector is used for managing object level permissions performance efficient way. 
It supports queryset filtering by permission. 
Also it allow every object in your project to behave as a user group. i.e. adding permissions and users with roles

Quick start
-----------

1. Add "protector" to your INSTALLED_APPS setting::

    INSTALLED_APPS = (
        ...
        'protector',
    )

3. Run `python manage.py migrate` to create the protector models.
