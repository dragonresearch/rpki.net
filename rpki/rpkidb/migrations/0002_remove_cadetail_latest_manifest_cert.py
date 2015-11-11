# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='cadetail',
            name='latest_manifest_cert',
        ),
    ]
