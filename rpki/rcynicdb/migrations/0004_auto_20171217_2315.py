# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rcynicdb', '0003_auto_20160301_0333'),
    ]

    operations = [
        migrations.CreateModel(
            name='RRDPZone',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('session_id', models.UUIDField()),
                ('serial', models.BigIntegerField()),
                ('updated', models.DateTimeField(null=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='rrdpsnapshot',
            name='retrieved',
        ),
        migrations.RemoveField(
            model_name='rpkiobject',
            name='snapshot',
        ),
        migrations.DeleteModel(
            name='RRDPSnapshot',
        ),
        migrations.AddField(
            model_name='rpkiobject',
            name='zone',
            field=models.ManyToManyField(to='rcynicdb.RRDPZone'),
        ),
    ]
