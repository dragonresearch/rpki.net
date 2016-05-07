# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.gui.gui_rpki_cache.models
import rpki.gui.models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AddressRange',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('prefix_min', rpki.gui.models.IPAddressField(db_index=True)),
                ('prefix_max', rpki.gui.models.IPAddressField(db_index=True)),
            ],
            options={
                'ordering': ('prefix_min',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='AddressRangeV6',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('prefix_min', rpki.gui.models.IPAddressField(db_index=True)),
                ('prefix_max', rpki.gui.models.IPAddressField(db_index=True)),
            ],
            options={
                'ordering': ('prefix_min',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ASRange',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('min', models.BigIntegerField(validators=[rpki.gui.models.validate_asn])),
                ('max', models.BigIntegerField(validators=[rpki.gui.models.validate_asn])),
            ],
            options={
                'ordering': ('min', 'max'),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Cert',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uri', models.TextField()),
                ('sha256', models.SlugField(unique=True, max_length=64)),
                ('not_before', models.DateTimeField()),
                ('not_after', models.DateTimeField()),
                ('ski', models.SlugField(max_length=40)),
                ('addresses', models.ManyToManyField(related_name='certs', to='gui_rpki_cache.AddressRange')),
                ('addresses_v6', models.ManyToManyField(related_name='certs', to='gui_rpki_cache.AddressRangeV6')),
                ('asns', models.ManyToManyField(related_name='certs', to='gui_rpki_cache.ASRange')),
                ('issuer', models.ForeignKey(related_name='children', to='gui_rpki_cache.Cert', null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Ghostbuster',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uri', models.TextField()),
                ('sha256', models.SlugField(unique=True, max_length=64)),
                ('not_before', models.DateTimeField()),
                ('not_after', models.DateTimeField()),
                ('full_name', models.CharField(max_length=40)),
                ('email_address', models.EmailField(max_length=254, null=True, blank=True)),
                ('organization', models.CharField(max_length=255, null=True, blank=True)),
                ('telephone', rpki.gui.gui_rpki_cache.models.TelephoneField(max_length=255, null=True, blank=True)),
                ('issuer', models.ForeignKey(related_name='ghostbusters', to='gui_rpki_cache.Cert')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ROA',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uri', models.TextField()),
                ('sha256', models.SlugField(unique=True, max_length=64)),
                ('not_before', models.DateTimeField()),
                ('not_after', models.DateTimeField()),
                ('asid', models.PositiveIntegerField()),
                ('issuer', models.ForeignKey(related_name='roas', to='gui_rpki_cache.Cert')),
            ],
            options={
                'ordering': ('asid',),
            },
        ),
        migrations.CreateModel(
            name='ROAPrefixV4',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('prefix_min', rpki.gui.models.IPAddressField(db_index=True)),
                ('prefix_max', rpki.gui.models.IPAddressField(db_index=True)),
                ('max_length', models.PositiveSmallIntegerField()),
            ],
            options={
                'ordering': ('prefix_min',),
            },
        ),
        migrations.CreateModel(
            name='ROAPrefixV6',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('prefix_min', rpki.gui.models.IPAddressField(db_index=True)),
                ('prefix_max', rpki.gui.models.IPAddressField(db_index=True)),
                ('max_length', models.PositiveSmallIntegerField()),
            ],
            options={
                'ordering': ('prefix_min',),
            },
        ),
        migrations.AddField(
            model_name='roa',
            name='prefixes',
            field=models.ManyToManyField(related_name='roas', to='gui_rpki_cache.ROAPrefixV4'),
        ),
        migrations.AddField(
            model_name='roa',
            name='prefixes_v6',
            field=models.ManyToManyField(related_name='roas', to='gui_rpki_cache.ROAPrefixV6'),
        ),
    ]
