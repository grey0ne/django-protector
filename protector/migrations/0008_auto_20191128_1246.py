# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2019-11-28 12:46
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import protector.managers


class Migration(migrations.Migration):

    dependencies = [
        ('protector', '0007_auto_20190604_1837'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='genericusertogroup',
            managers=[
                ('objects', protector.managers.GenericUserToGroupManager()),
            ],
        ),
        migrations.AlterModelManagers(
            name='ownertopermission',
            managers=[
                ('objects', protector.managers.OwnerToPermissionManager()),
            ],
        ),
        migrations.AlterField(
            model_name='historyownertopermission',
            name='content_type',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='historyownertopermission_restriction_group_relations', to='contenttypes.ContentType', verbose_name='object type'),
        ),
        migrations.AlterField(
            model_name='historyownertopermission',
            name='object_id',
            field=models.PositiveIntegerField(blank=True, null=True, verbose_name='object id'),
        ),
        migrations.AlterField(
            model_name='ownertopermission',
            name='content_type',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='ownertopermission_restriction_group_relations', to='contenttypes.ContentType', verbose_name='object type'),
        ),
        migrations.AlterField(
            model_name='ownertopermission',
            name='object_id',
            field=models.PositiveIntegerField(blank=True, null=True, verbose_name='object id'),
        ),
    ]