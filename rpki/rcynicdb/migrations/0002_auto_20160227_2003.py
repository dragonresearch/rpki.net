# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rcynicdb', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='retrieval',
            name='finished',
            field=models.DateTimeField(null=True),
        ),
        migrations.AlterField(
            model_name='retrieval',
            name='successful',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='rrdpsnapshot',
            name='retrieved',
            field=models.OneToOneField(null=True, to='rcynicdb.Retrieval'),
        ),
    ]
