# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gui_rpki_cache', '0002_auto_20160411_2311'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ghostbuster',
            name='issuer',
            field=models.ForeignKey(related_name='ghostbusters', to='gui_rpki_cache.Cert', null=True),
        ),
        migrations.AlterField(
            model_name='roa',
            name='issuer',
            field=models.ForeignKey(related_name='roas', to='gui_rpki_cache.Cert', null=True),
        ),
    ]
