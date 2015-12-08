=====
Protector
=====
.. image:: https://img.shields.io/coveralls/grey0ne/django-protector.svg
       :target: https://coveralls.io/r/grey0ne/django-protector?branch=master

.. image:: https://img.shields.io/travis/grey0ne/django-protector/master.svg
       :target: https://travis-ci.org/grey0ne/django-protector

Protector is used for managing object level permissions in performance efficient way. 
It supports queryset filtering by permission and user. 
Also it allow every object in your project to behave as a user group. i.e. adding permissions and users with roles.

Quick start
-----------

1. Install from pip (it will also install required django-mptt)::

    pip install django-protector

2. Add "protector" to your INSTALLED_APPS setting::

    INSTALLED_APPS = (
        ...
        'protector',
    )

3. Add protector authentication backend. Also you should remove default auth backend::

    AUTHENTICATION_BACKENDS = (
        ...
        'protector.backends.GenericPermissionBackend'
    )

4. Make some model your default group::

    PROTECTOR_GENERIC_GROUP = 'users.group'

5. Run `python manage.py migrate` to create the protector models and copy existing user permissions

Now you can check permissions on objects like this::
    
    user.has_perm('some_app.some_perm', user)

Or filter any queryset by permission::

    from protector.models import filter_queryset_by_permission
    filtered_qset = filter_queryset_by_permission(some_qset, user, 'some_app.some_perm')

Additional steps
----------------

1. Add GenericPermsMixin to your User model to conviniently add permissions and groups::

    class User(UserGenericPermsMixin, AbstractBaseUser)

2. Create some group models. Every model in your project could now behave like a group. You could inherit your models from abstract group to have convinient fields for users and permissions::

    class Group(AbstractGenericGroup):

4. Inherit your Querysets from PermissionQuerySet to conviniently filter by permission::
    
    some_qset.filter_by_permission(user, 'some_app.some_perm')

Now you can manipulate permissions and groups::

    user.permissions.all()
    user.permissions.add(permission)
    user.groups.all()
    group.permissions.add(permission)


Restricting access to objects
-----------------------------

This is somewhat different from just filtering queryset by permission

1. Inherit your model from Restricted::

    class Comment(Restricted)

2. Inherit model manager from RestrictedManager::

    class CommentManager(RestrictedManager):

3. Restricted contains some additional fields so you need to run makemigration for your app

4. Now you can restrict instances of your model::
    
    comment.restrict()

To enable user view one or all restricted objects::
    
    user.permissions.add(Restricted.get_view_permission(), comment)
    user.permissions.add(Restricted.get_view_permission())

To filter model objects visible by user::
    
    Comment.objects.visible(user)


Global Permissions
-----------------------------

You could define Template-like permissions. For example you want all group moderators to have edit_permission on their group.
Such templates could be created In Global Group Permissions admin interface. You should choose ContentType of your group, roles and, of course, permission those roles should have.
No further actions required::

    user.has_perm('someapp.edit_permission', somegroup)

would return true if user is moderator in somegroup

   
Permission on Foreign Key to User
------------------------------

Every so often you would like owners of your objects to have some permissions of their objects.
Easy peasy.
You should inherit you object, for example TestPost from AbstractGenericGroup
Like so::

    class TestPost(AbstractGenericGroup):
        SUBSCRIBER = 1
        AUTHOR = 2
        ROLES = (
            (SUBSCRIBER, 'Subscriber'),
            (AUTHOR, 'Author')
        )
        author = models.ForeignKey(to=TestUser)

        MEMBER_FOREIGN_KEY_FIELDS = (
            ('author', AUTHOR),
        )

        class Meta:
            permissions = (
                ('manage_post', 'Manage Post'),
            )


MEMBER_FOREIGN_KEY_FIELDS defines which foreign key gets which role.

Notice: This is accomplished via some denormalization and works through create, save and update model and manager methods overloading
