# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.irdb.models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BSC',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
                ('handle', rpki.irdb.models.HandleField(max_length=120)),
                ('pkcs10', rpki.fields.PKCS10Field()),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Child',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
                ('handle', rpki.irdb.models.HandleField(max_length=120)),
                ('ta', rpki.fields.CertificateField()),
                ('valid_until', rpki.fields.SundialField()),
                ('name', models.TextField(null=True, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='ChildASN',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('start_as', models.BigIntegerField()),
                ('end_as', models.BigIntegerField()),
                ('child', models.ForeignKey(related_name='asns', to='irdb.Child')),
            ],
        ),
        migrations.CreateModel(
            name='ChildNet',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('start_ip', models.CharField(max_length=40)),
                ('end_ip', models.CharField(max_length=40)),
                ('version', rpki.fields.EnumField(choices=[(4, b'IPv4'), (6, b'IPv6')])),
                ('child', models.ForeignKey(related_name='address_ranges', to='irdb.Child')),
            ],
        ),
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
                ('handle', rpki.irdb.models.HandleField(max_length=120)),
                ('ta', rpki.fields.CertificateField()),
                ('sia_base', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='EECertificateRequest',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('valid_until', rpki.fields.SundialField()),
                ('pkcs10', rpki.fields.PKCS10Field()),
                ('gski', models.CharField(max_length=27)),
                ('cn', models.CharField(max_length=64)),
                ('sn', models.CharField(max_length=64)),
                ('eku', models.TextField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='EECertificateRequestASN',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('start_as', models.BigIntegerField()),
                ('end_as', models.BigIntegerField()),
                ('ee_certificate_request', models.ForeignKey(related_name='asns', to='irdb.EECertificateRequest')),
            ],
        ),
        migrations.CreateModel(
            name='EECertificateRequestNet',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('start_ip', models.CharField(max_length=40)),
                ('end_ip', models.CharField(max_length=40)),
                ('version', rpki.fields.EnumField(choices=[(4, b'IPv4'), (6, b'IPv6')])),
                ('ee_certificate_request', models.ForeignKey(related_name='address_ranges', to='irdb.EECertificateRequest')),
            ],
        ),
        migrations.CreateModel(
            name='GhostbusterRequest',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('vcard', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='HostedCA',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
            ],
        ),
        migrations.CreateModel(
            name='Referral',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
                ('private_key', rpki.fields.RSAPrivateKeyField()),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Repository',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
                ('handle', rpki.irdb.models.HandleField(max_length=120)),
                ('ta', rpki.fields.CertificateField()),
                ('client_handle', rpki.irdb.models.HandleField(max_length=120)),
                ('service_uri', models.CharField(max_length=255)),
                ('sia_base', models.TextField()),
                ('rrdp_notification_uri', models.TextField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='ResourceHolderCA',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
                ('private_key', rpki.fields.RSAPrivateKeyField()),
                ('latest_crl', rpki.fields.CRLField()),
                ('next_serial', models.BigIntegerField(default=1)),
                ('next_crl_number', models.BigIntegerField(default=1)),
                ('last_crl_update', rpki.fields.SundialField()),
                ('next_crl_update', rpki.fields.SundialField()),
                ('handle', rpki.irdb.models.HandleField(unique=True, max_length=120)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ResourceHolderRevocation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('serial', models.BigIntegerField()),
                ('revoked', rpki.fields.SundialField()),
                ('expires', rpki.fields.SundialField()),
                ('issuer', models.ForeignKey(related_name='revocations', to='irdb.ResourceHolderCA')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ROARequest',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('asn', models.BigIntegerField()),
                ('issuer', models.ForeignKey(related_name='roa_requests', to='irdb.ResourceHolderCA')),
            ],
        ),
        migrations.CreateModel(
            name='ROARequestPrefix',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('version', rpki.fields.EnumField(choices=[(4, b'IPv4'), (6, b'IPv6')])),
                ('prefix', models.CharField(max_length=40)),
                ('prefixlen', models.PositiveSmallIntegerField()),
                ('max_prefixlen', models.PositiveSmallIntegerField()),
                ('roa_request', models.ForeignKey(related_name='prefixes', to='irdb.ROARequest')),
            ],
        ),
        migrations.CreateModel(
            name='ServerCA',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
                ('private_key', rpki.fields.RSAPrivateKeyField()),
                ('latest_crl', rpki.fields.CRLField()),
                ('next_serial', models.BigIntegerField(default=1)),
                ('next_crl_number', models.BigIntegerField(default=1)),
                ('last_crl_update', rpki.fields.SundialField()),
                ('next_crl_update', rpki.fields.SundialField()),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ServerEE',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('certificate', rpki.fields.CertificateField()),
                ('private_key', rpki.fields.RSAPrivateKeyField()),
                ('purpose', rpki.fields.EnumField(choices=[(1, b'rpkid'), (2, b'pubd'), (3, b'irdbd'), (4, b'irbe')])),
                ('issuer', models.ForeignKey(related_name='ee_certificates', to='irdb.ServerCA')),
            ],
        ),
        migrations.CreateModel(
            name='ServerRevocation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('serial', models.BigIntegerField()),
                ('revoked', rpki.fields.SundialField()),
                ('expires', rpki.fields.SundialField()),
                ('issuer', models.ForeignKey(related_name='revocations', to='irdb.ServerCA')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Turtle',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('service_uri', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Parent',
            fields=[
                ('turtle_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='irdb.Turtle')),
                ('certificate', rpki.fields.CertificateField()),
                ('handle', rpki.irdb.models.HandleField(max_length=120)),
                ('ta', rpki.fields.CertificateField()),
                ('parent_handle', rpki.irdb.models.HandleField(max_length=120)),
                ('child_handle', rpki.irdb.models.HandleField(max_length=120)),
                ('repository_type', rpki.fields.EnumField(choices=[(1, b'none'), (2, b'offer'), (3, b'referral')])),
                ('referrer', rpki.irdb.models.HandleField(max_length=120, null=True, blank=True)),
                ('referral_authorization', rpki.irdb.models.SignedReferralField(null=True)),
                ('issuer', models.ForeignKey(related_name='parents', to='irdb.ResourceHolderCA')),
            ],
            bases=('irdb.turtle', models.Model),
        ),
        migrations.CreateModel(
            name='Rootd',
            fields=[
                ('turtle_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='irdb.Turtle')),
                ('certificate', rpki.fields.CertificateField()),
                ('private_key', rpki.fields.RSAPrivateKeyField()),
                ('issuer', models.OneToOneField(related_name='rootd', to='irdb.ResourceHolderCA')),
            ],
            options={
                'abstract': False,
            },
            bases=('irdb.turtle', models.Model),
        ),
        migrations.AddField(
            model_name='repository',
            name='issuer',
            field=models.ForeignKey(related_name='repositories', to='irdb.ResourceHolderCA'),
        ),
        migrations.AddField(
            model_name='repository',
            name='turtle',
            field=models.OneToOneField(related_name='repository', to='irdb.Turtle'),
        ),
        migrations.AddField(
            model_name='referral',
            name='issuer',
            field=models.OneToOneField(related_name='referral_certificate', to='irdb.ResourceHolderCA'),
        ),
        migrations.AddField(
            model_name='hostedca',
            name='hosted',
            field=models.OneToOneField(related_name='hosted_by', to='irdb.ResourceHolderCA'),
        ),
        migrations.AddField(
            model_name='hostedca',
            name='issuer',
            field=models.ForeignKey(to='irdb.ServerCA'),
        ),
        migrations.AddField(
            model_name='ghostbusterrequest',
            name='issuer',
            field=models.ForeignKey(related_name='ghostbuster_requests', to='irdb.ResourceHolderCA'),
        ),
        migrations.AddField(
            model_name='eecertificaterequest',
            name='issuer',
            field=models.ForeignKey(related_name='ee_certificate_requests', to='irdb.ResourceHolderCA'),
        ),
        migrations.AddField(
            model_name='client',
            name='issuer',
            field=models.ForeignKey(related_name='clients', to='irdb.ServerCA'),
        ),
        migrations.AddField(
            model_name='child',
            name='issuer',
            field=models.ForeignKey(related_name='children', to='irdb.ResourceHolderCA'),
        ),
        migrations.AddField(
            model_name='bsc',
            name='issuer',
            field=models.ForeignKey(related_name='bscs', to='irdb.ResourceHolderCA'),
        ),
        migrations.AlterUniqueTogether(
            name='serverrevocation',
            unique_together=set([('issuer', 'serial')]),
        ),
        migrations.AlterUniqueTogether(
            name='serveree',
            unique_together=set([('issuer', 'purpose')]),
        ),
        migrations.AlterUniqueTogether(
            name='roarequestprefix',
            unique_together=set([('roa_request', 'version', 'prefix', 'prefixlen', 'max_prefixlen')]),
        ),
        migrations.AlterUniqueTogether(
            name='resourceholderrevocation',
            unique_together=set([('issuer', 'serial')]),
        ),
        migrations.AlterUniqueTogether(
            name='repository',
            unique_together=set([('issuer', 'handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='hostedca',
            unique_together=set([('issuer', 'hosted')]),
        ),
        migrations.AddField(
            model_name='ghostbusterrequest',
            name='parent',
            field=models.ForeignKey(related_name='ghostbuster_requests', to='irdb.Parent', null=True),
        ),
        migrations.AlterUniqueTogether(
            name='eecertificaterequestnet',
            unique_together=set([('ee_certificate_request', 'start_ip', 'end_ip', 'version')]),
        ),
        migrations.AlterUniqueTogether(
            name='eecertificaterequestasn',
            unique_together=set([('ee_certificate_request', 'start_as', 'end_as')]),
        ),
        migrations.AlterUniqueTogether(
            name='eecertificaterequest',
            unique_together=set([('issuer', 'gski')]),
        ),
        migrations.AlterUniqueTogether(
            name='client',
            unique_together=set([('issuer', 'handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='childnet',
            unique_together=set([('child', 'start_ip', 'end_ip', 'version')]),
        ),
        migrations.AlterUniqueTogether(
            name='childasn',
            unique_together=set([('child', 'start_as', 'end_as')]),
        ),
        migrations.AlterUniqueTogether(
            name='child',
            unique_together=set([('issuer', 'handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='bsc',
            unique_together=set([('issuer', 'handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='parent',
            unique_together=set([('issuer', 'handle')]),
        ),
    ]
