# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0006_auto_20151019_0032'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Self',
            new_name='Tenant',
        ),
        migrations.RenameField(
            model_name='bsc',
            old_name='self',
            new_name='tenant',
        ),
        migrations.RenameField(
            model_name='child',
            old_name='self',
            new_name='tenant',
        ),
        migrations.RenameField(
            model_name='eecertificate',
            old_name='self',
            new_name='tenant',
        ),
        migrations.RenameField(
            model_name='ghostbuster',
            old_name='self',
            new_name='tenant',
        ),
        migrations.RenameField(
            model_name='parent',
            old_name='self',
            new_name='tenant',
        ),
        migrations.RenameField(
            model_name='repository',
            old_name='self',
            new_name='tenant',
        ),
        migrations.RenameField(
            model_name='roa',
            old_name='self',
            new_name='tenant',
        ),
        migrations.RenameField(
            model_name='tenant',
            old_name='self_handle',
            new_name='tenant_handle',
        ),
        migrations.AlterUniqueTogether(
            name='bsc',
            unique_together=set([('tenant', 'bsc_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='child',
            unique_together=set([('tenant', 'child_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='parent',
            unique_together=set([('tenant', 'parent_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='repository',
            unique_together=set([('tenant', 'repository_handle')]),
        ),
    ]
