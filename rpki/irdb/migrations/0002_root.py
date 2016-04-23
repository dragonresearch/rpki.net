# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('irdb', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='parent',
            name='asn_resources',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='parent',
            name='ipv4_resources',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='parent',
            name='ipv6_resources',
            field=models.TextField(blank=True),
        ),
    ]
