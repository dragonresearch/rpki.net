# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0002_remove_cadetail_latest_manifest_cert'),
    ]

    operations = [
        migrations.RenameField(
            model_name='ca',
            old_name='last_crl_sn',
            new_name='last_crl_manifest_number',
        ),
        migrations.RemoveField(
            model_name='ca',
            name='last_manifest_sn',
        ),
        migrations.RemoveField(
            model_name='ca',
            name='next_crl_update',
        ),
        migrations.RemoveField(
            model_name='ca',
            name='next_manifest_update',
        ),
        migrations.AddField(
            model_name='cadetail',
            name='next_crl_manifest_update',
            field=rpki.fields.SundialField(null=True),
        ),
    ]
