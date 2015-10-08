# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('client_handle', models.CharField(unique=True, max_length=255)),
                ('base_uri', models.TextField()),
                ('bpki_cert', rpki.fields.CertificateField(default=None, serialize=False, blank=True)),
                ('bpki_glue', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('last_cms_timestamp', rpki.fields.SundialField(null=True, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Delta',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('serial', models.BigIntegerField()),
                ('xml', models.TextField()),
                ('hash', models.CharField(max_length=64)),
                ('expires', rpki.fields.SundialField()),
            ],
        ),
        migrations.CreateModel(
            name='PublishedObject',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uri', models.CharField(max_length=255)),
                ('der', rpki.fields.BlobField(default=None, serialize=False, blank=True)),
                ('hash', models.CharField(max_length=64)),
                ('client', models.ForeignKey(to='pubdb.Client')),
            ],
        ),
        migrations.CreateModel(
            name='Session',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', models.CharField(unique=True, max_length=36)),
                ('serial', models.BigIntegerField()),
                ('snapshot', models.TextField(blank=True)),
                ('hash', models.CharField(max_length=64, blank=True)),
            ],
        ),
        migrations.AddField(
            model_name='publishedobject',
            name='session',
            field=models.ForeignKey(to='pubdb.Session'),
        ),
        migrations.AddField(
            model_name='delta',
            name='session',
            field=models.ForeignKey(to='pubdb.Session'),
        ),
        migrations.AlterUniqueTogether(
            name='publishedobject',
            unique_together=set([('session', 'hash'), ('session', 'uri')]),
        ),
    ]
