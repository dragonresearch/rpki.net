# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='parent',
            old_name='bpki_cms_cert',
            new_name='bpki_cert',
        ),
        migrations.RenameField(
            model_name='parent',
            old_name='bpki_cms_glue',
            new_name='bpki_glue',
        ),
        migrations.AddField(
            model_name='repository',
            name='rrdp_notification_uri',
            field=models.TextField(null=True),
        ),
    ]
