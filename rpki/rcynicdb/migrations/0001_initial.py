# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Authenticated',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('started', models.DateTimeField()),
                ('finished', models.DateTimeField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Retrieval',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uri', models.TextField()),
                ('started', models.DateTimeField()),
                ('finished', models.DateTimeField()),
                ('successful', models.BooleanField()),
            ],
        ),
        migrations.CreateModel(
            name='RPKIObject',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('der', models.BinaryField()),
                ('uri', models.TextField()),
                ('aki', models.SlugField(max_length=40)),
                ('ski', models.SlugField(max_length=40)),
                ('sha256', models.SlugField(unique=True, max_length=64)),
                ('authenticated', models.ManyToManyField(to='rcynicdb.Authenticated')),
                ('retrieved', models.ForeignKey(to='rcynicdb.Retrieval')),
            ],
        ),
        migrations.CreateModel(
            name='RRDPSnapshot',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('session_id', models.UUIDField()),
                ('serial', models.BigIntegerField()),
                ('retrieved', models.OneToOneField(to='rcynicdb.Retrieval')),
            ],
        ),
        migrations.AddField(
            model_name='rpkiobject',
            name='snapshot',
            field=models.ManyToManyField(to='rcynicdb.RRDPSnapshot'),
        ),
    ]
