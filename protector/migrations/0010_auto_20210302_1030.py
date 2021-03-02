# Generated by Django 3.1.5 on 2021-03-02 10:30

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('contenttypes', '0002_remove_content_type_name'),
        ('protector', '0009_auto_20210302_1013'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='genericusertogroup',
            unique_together={('group_content_type', 'group_id', 'user')},
        ),
        migrations.AlterIndexTogether(
            name='historygenericusertogroup',
            index_together={('group_content_type', 'group_id', 'user')},
        ),
    ]
