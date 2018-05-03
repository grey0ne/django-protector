# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings
import mptt.fields


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('auth', '0006_require_contenttypes_0002'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GenericGlobalPerm',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('roles', models.IntegerField(default=1, verbose_name='roles')),
                ('content_type', models.ForeignKey(related_name='global_perms', default=1, to='contenttypes.ContentType', on_delete=models.CASCADE)),
                ('permission', models.ForeignKey(to='auth.Permission', on_delete=models.CASCADE)),
            ],
            options={
                'verbose_name': 'global group permission',
                'verbose_name_plural': 'global group permissions',
            },
        ),
        migrations.CreateModel(
            name='GenericUserToGroup',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('roles', models.IntegerField(null=True, verbose_name='roles', blank=True)),
                ('group_id', models.PositiveIntegerField()),
                ('date_joined', models.DateTimeField(auto_now_add=True, verbose_name='date joined')),
                ('group_content_type', models.ForeignKey(to='contenttypes.ContentType', on_delete=models.CASCADE)),
                ('responsible', models.ForeignKey(related_name='created_group_relations', verbose_name='responsible', blank=True, to=settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)),
                ('user', models.ForeignKey(related_name='generic_group_relations', to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE)),
            ],
            options={
                'verbose_name': 'user to group link',
                'verbose_name_plural': 'user to group links',
            },
        ),
        migrations.CreateModel(
            name='OwnerToPermission',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('object_id', models.PositiveIntegerField(default=0, verbose_name='object id')),
                ('owner_object_id', models.PositiveIntegerField(verbose_name='owner id')),
                ('date_issued', models.DateTimeField(auto_now_add=True, verbose_name='date issued')),
                ('roles', models.IntegerField(default=1, verbose_name='roles')),
                ('content_type', models.ForeignKey(related_name='restriction_group_relations', default=1, verbose_name='object type', to='contenttypes.ContentType', on_delete=models.CASCADE)),
                ('owner_content_type', models.ForeignKey(related_name='restricted_object_relations', verbose_name='owner type', to='contenttypes.ContentType', on_delete=models.CASCADE)),
                ('permission', models.ForeignKey(related_name='generic_restriction_relations', verbose_name='permission', to='auth.Permission', on_delete=models.CASCADE)),
                ('responsible', models.ForeignKey(related_name='created_permission_relations', verbose_name='responsible', blank=True, to=settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)),
            ],
            options={
                'permissions': (('add_permission', 'add permission'), ('view_restricted_objects', 'view restricted objects')),
                'verbose_name': 'owner to permission link',
                'verbose_name_plural': 'owner to permission links',
            },
        ),
        migrations.CreateModel(
            name='Restriction',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('object_id', models.PositiveIntegerField()),
                ('lft', models.PositiveIntegerField(editable=False, db_index=True)),
                ('rght', models.PositiveIntegerField(editable=False, db_index=True)),
                ('tree_id', models.PositiveIntegerField(editable=False, db_index=True)),
                ('level', models.PositiveIntegerField(editable=False, db_index=True)),
                ('content_type', models.ForeignKey(to='contenttypes.ContentType', on_delete=models.CASCADE)),
                ('parent', mptt.fields.TreeForeignKey(related_name='children', verbose_name='parent object', blank=True, to='protector.Restriction', null=True, on_delete=models.SET_NULL)),
            ],
            options={
                'verbose_name': 'Object restriction',
                'verbose_name_plural': 'Objects restrictions',
            },
        ),
        migrations.AlterUniqueTogether(
            name='restriction',
            unique_together=set([('object_id', 'content_type')]),
        ),
        migrations.AlterUniqueTogether(
            name='ownertopermission',
            unique_together=set([('content_type', 'object_id', 'owner_content_type', 'owner_object_id', 'permission')]),
        ),
        migrations.AlterIndexTogether(
            name='ownertopermission',
            index_together=set([('owner_content_type', 'owner_object_id'), ('content_type', 'object_id', 'permission')]),
        ),
        migrations.AlterUniqueTogether(
            name='genericusertogroup',
            unique_together=set([('group_id', 'group_content_type', 'user')]),
        ),
        migrations.AlterUniqueTogether(
            name='genericglobalperm',
            unique_together=set([('content_type', 'permission')]),
        ),
    ]
