# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('irdb', '0002_remove_client_parent_handle'),
    ]

    operations = [
        migrations.AddField(
            model_name='repository',
            name='rrdp_notification_uri',
            field=models.TextField(null=True),
        ),
    ]
