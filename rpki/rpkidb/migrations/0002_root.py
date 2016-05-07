# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='parent',
            name='root_asn_resources',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='parent',
            name='root_ipv4_resources',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='parent',
            name='root_ipv6_resources',
            field=models.TextField(default=''),
        ),
    ]
