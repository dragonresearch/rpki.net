# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
        ('irdb', '0003_repository_rrdp_notification_uri'),
    ]

    operations = [
        migrations.AlterField(
            model_name='referral',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(default=None, serialize=False, blank=True),
        ),
        migrations.AlterField(
            model_name='resourceholderca',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(default=None, serialize=False, blank=True),
        ),
        migrations.AlterField(
            model_name='rootd',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(default=None, serialize=False, blank=True),
        ),
        migrations.AlterField(
            model_name='serverca',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(default=None, serialize=False, blank=True),
        ),
        migrations.AlterField(
            model_name='serveree',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(default=None, serialize=False, blank=True),
        ),
    ]
