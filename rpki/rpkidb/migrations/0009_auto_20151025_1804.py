# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0008_auto_20151023_2151'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='childcert',
            name='ski',
        ),
        migrations.RemoveField(
            model_name='eecertificate',
            name='ski',
        ),
        migrations.AddField(
            model_name='childcert',
            name='gski',
            field=models.CharField(default='fred', max_length=27),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='eecertificate',
            name='gski',
            field=models.CharField(default='wilma', max_length=27),
            preserve_default=False,
        ),
    ]
