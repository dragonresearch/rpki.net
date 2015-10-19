# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0003_auto_20151018_1600'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bsc',
            name='private_key_id',
            field=rpki.fields.RSAPrivateKeyField(default=None, serialize=False, blank=True),
        ),
        migrations.AlterField(
            model_name='cadetail',
            name='manifest_private_key_id',
            field=rpki.fields.RSAPrivateKeyField(default=None, serialize=False, null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='cadetail',
            name='private_key_id',
            field=rpki.fields.RSAPrivateKeyField(default=None, serialize=False, null=True, blank=True),
        ),
    ]
