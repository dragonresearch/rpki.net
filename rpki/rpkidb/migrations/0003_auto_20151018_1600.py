# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0002_auto_20151015_2213'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bsc',
            name='hash_alg',
            field=rpki.fields.EnumField(default='sha256', choices=[(1, 'sha256')]),
        ),
        migrations.AlterField(
            model_name='cadetail',
            name='manifest_public_key',
            field=rpki.fields.PublicKeyField(default=None, serialize=False, null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='cadetail',
            name='public_key',
            field=rpki.fields.PublicKeyField(default=None, serialize=False, null=True, blank=True),
        ),
    ]
