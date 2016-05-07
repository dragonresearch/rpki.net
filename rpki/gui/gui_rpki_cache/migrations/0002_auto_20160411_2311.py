# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gui_rpki_cache', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='cert',
            name='sha256',
        ),
        migrations.RemoveField(
            model_name='ghostbuster',
            name='sha256',
        ),
        migrations.RemoveField(
            model_name='roa',
            name='sha256',
        ),
        migrations.AlterField(
            model_name='cert',
            name='issuer',
            field=models.ForeignKey(to='gui_rpki_cache.Cert', null=True),
        ),
        migrations.AlterField(
            model_name='ghostbuster',
            name='issuer',
            field=models.ForeignKey(to='gui_rpki_cache.Cert', null=True),
        ),
        migrations.AlterField(
            model_name='roa',
            name='issuer',
            field=models.ForeignKey(to='gui_rpki_cache.Cert', null=True),
        ),
    ]
