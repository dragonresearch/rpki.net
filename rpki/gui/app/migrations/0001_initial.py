# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings
import rpki.gui.models
import rpki.gui.app.models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('irdb', '0001_initial'),
        ('routeview', '__first__'),
    ]

    operations = [
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('severity', models.SmallIntegerField(default=0, choices=[(0, b'info'), (1, b'warning'), (2, b'error')])),
                ('when', models.DateTimeField(auto_now_add=True)),
                ('seen', models.BooleanField(default=False)),
                ('subject', models.CharField(max_length=66)),
                ('text', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='ConfACL',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
            ],
        ),
        migrations.CreateModel(
            name='GhostbusterRequest',
            fields=[
                ('ghostbusterrequest_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='irdb.GhostbusterRequest')),
                ('full_name', models.CharField(max_length=40)),
                ('family_name', models.CharField(max_length=20)),
                ('given_name', models.CharField(max_length=20)),
                ('additional_name', models.CharField(max_length=20, null=True, blank=True)),
                ('honorific_prefix', models.CharField(max_length=10, null=True, blank=True)),
                ('honorific_suffix', models.CharField(max_length=10, null=True, blank=True)),
                ('email_address', models.EmailField(max_length=254, null=True, blank=True)),
                ('organization', models.CharField(max_length=255, null=True, blank=True)),
                ('telephone', rpki.gui.app.models.TelephoneField(max_length=40, null=True, blank=True)),
                ('box', models.CharField(max_length=40, null=True, verbose_name=b'P.O. Box', blank=True)),
                ('extended', models.CharField(max_length=255, null=True, blank=True)),
                ('street', models.CharField(max_length=255, null=True, blank=True)),
                ('city', models.CharField(max_length=40, null=True, blank=True)),
                ('region', models.CharField(help_text=b'state or province', max_length=40, null=True, blank=True)),
                ('code', models.CharField(max_length=40, null=True, verbose_name=b'Postal Code', blank=True)),
                ('country', models.CharField(max_length=40, null=True, blank=True)),
            ],
            options={
                'ordering': ('family_name', 'given_name'),
            },
            bases=('irdb.ghostbusterrequest',),
        ),
        migrations.CreateModel(
            name='ResourceCert',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('not_before', models.DateTimeField()),
                ('not_after', models.DateTimeField()),
                ('uri', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='ResourceRangeAddressV4',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('prefix_min', rpki.gui.models.IPAddressField(db_index=True)),
                ('prefix_max', rpki.gui.models.IPAddressField(db_index=True)),
                ('cert', models.ForeignKey(related_name='address_ranges', to='app.ResourceCert')),
            ],
            options={
                'ordering': ('prefix_min',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ResourceRangeAddressV6',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('prefix_min', rpki.gui.models.IPAddressField(db_index=True)),
                ('prefix_max', rpki.gui.models.IPAddressField(db_index=True)),
                ('cert', models.ForeignKey(related_name='address_ranges_v6', to='app.ResourceCert')),
            ],
            options={
                'ordering': ('prefix_min',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ResourceRangeAS',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('min', models.BigIntegerField(validators=[rpki.gui.models.validate_asn])),
                ('max', models.BigIntegerField(validators=[rpki.gui.models.validate_asn])),
                ('cert', models.ForeignKey(related_name='asn_ranges', to='app.ResourceCert')),
            ],
            options={
                'ordering': ('min', 'max'),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Timestamp',
            fields=[
                ('name', models.CharField(max_length=30, serialize=False, primary_key=True)),
                ('ts', models.DateTimeField()),
            ],
        ),
        migrations.CreateModel(
            name='Child',
            fields=[
            ],
            options={
                'proxy': True,
                'verbose_name_plural': 'children',
            },
            bases=('irdb.child',),
        ),
        migrations.CreateModel(
            name='ChildASN',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('irdb.childasn',),
        ),
        migrations.CreateModel(
            name='ChildNet',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('irdb.childnet',),
        ),
        migrations.CreateModel(
            name='Client',
            fields=[
            ],
            options={
                'verbose_name': 'Client',
                'proxy': True,
            },
            bases=('irdb.client',),
        ),
        migrations.CreateModel(
            name='Conf',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('irdb.resourceholderca',),
        ),
        migrations.CreateModel(
            name='Parent',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('irdb.parent',),
        ),
        migrations.CreateModel(
            name='Repository',
            fields=[
            ],
            options={
                'verbose_name': 'Repository',
                'proxy': True,
                'verbose_name_plural': 'Repositories',
            },
            bases=('irdb.repository',),
        ),
        migrations.CreateModel(
            name='ROARequest',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('irdb.roarequest',),
        ),
        migrations.CreateModel(
            name='ROARequestPrefix',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('irdb.roarequestprefix',),
        ),
        migrations.CreateModel(
            name='RouteOrigin',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('routeview.routeorigin',),
        ),
        migrations.CreateModel(
            name='RouteOriginV6',
            fields=[
            ],
            options={
                'proxy': True,
            },
            bases=('routeview.routeoriginv6',),
        ),
        migrations.AddField(
            model_name='resourcecert',
            name='conf',
            field=models.ForeignKey(related_name='certs', to='app.Conf'),
        ),
        migrations.AddField(
            model_name='resourcecert',
            name='parent',
            field=models.ForeignKey(related_name='certs', to='app.Parent', null=True),
        ),
        migrations.AddField(
            model_name='confacl',
            name='conf',
            field=models.ForeignKey(to='app.Conf'),
        ),
        migrations.AddField(
            model_name='confacl',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='alert',
            name='conf',
            field=models.ForeignKey(related_name='alerts', to='app.Conf'),
        ),
        migrations.AlterUniqueTogether(
            name='confacl',
            unique_together=set([('user', 'conf')]),
        ),
    ]
