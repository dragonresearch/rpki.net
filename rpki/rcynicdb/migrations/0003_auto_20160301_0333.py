# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rcynicdb', '0002_auto_20160227_2003'),
    ]

    operations = [
        migrations.AlterField(
            model_name='retrieval',
            name='finished',
            field=models.DateTimeField(),
        ),
        migrations.AlterField(
            model_name='retrieval',
            name='successful',
            field=models.BooleanField(),
        ),
    ]
