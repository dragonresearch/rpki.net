# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BSC',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('bsc_handle', models.SlugField(max_length=255)),
                ('private_key_id', rpki.fields.RSAPrivateKeyField()),
                ('pkcs10_request', rpki.fields.PKCS10Field()),
                ('hash_alg', rpki.fields.EnumField(default='sha256', choices=[(1, 'sha256')])),
                ('signing_cert', rpki.fields.CertificateField(null=True)),
                ('signing_cert_crl', rpki.fields.CRLField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='CA',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('last_crl_manifest_number', models.BigIntegerField(default=1)),
                ('last_issued_sn', models.BigIntegerField(default=1)),
                ('sia_uri', models.TextField(null=True)),
                ('parent_resource_class', models.TextField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='CADetail',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('public_key', rpki.fields.PublicKeyField(null=True)),
                ('private_key_id', rpki.fields.RSAPrivateKeyField(null=True)),
                ('latest_crl', rpki.fields.CRLField(null=True)),
                ('crl_published', rpki.fields.SundialField(null=True)),
                ('latest_ca_cert', rpki.fields.CertificateField(null=True)),
                ('manifest_private_key_id', rpki.fields.RSAPrivateKeyField(null=True)),
                ('manifest_public_key', rpki.fields.PublicKeyField(null=True)),
                ('latest_manifest', rpki.fields.ManifestField(null=True)),
                ('manifest_published', rpki.fields.SundialField(null=True)),
                ('next_crl_manifest_update', rpki.fields.SundialField(null=True)),
                ('state', rpki.fields.EnumField(choices=[(1, 'pending'), (2, 'active'), (3, 'deprecated'), (4, 'revoked')])),
                ('ca_cert_uri', models.TextField(null=True)),
                ('ca', models.ForeignKey(related_name='ca_details', to='rpkidb.CA')),
            ],
        ),
        migrations.CreateModel(
            name='Child',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('child_handle', models.SlugField(max_length=255)),
                ('bpki_cert', rpki.fields.CertificateField(null=True)),
                ('bpki_glue', rpki.fields.CertificateField(null=True)),
                ('last_cms_timestamp', rpki.fields.SundialField(null=True)),
                ('bsc', models.ForeignKey(related_name='children', to='rpkidb.BSC')),
            ],
        ),
        migrations.CreateModel(
            name='ChildCert',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('cert', rpki.fields.CertificateField()),
                ('published', rpki.fields.SundialField(null=True)),
                ('gski', models.CharField(max_length=27)),
                ('ca_detail', models.ForeignKey(related_name='child_certs', to='rpkidb.CADetail')),
                ('child', models.ForeignKey(related_name='child_certs', to='rpkidb.Child')),
            ],
        ),
        migrations.CreateModel(
            name='EECertificate',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('gski', models.CharField(max_length=27)),
                ('cert', rpki.fields.CertificateField()),
                ('published', rpki.fields.SundialField(null=True)),
                ('ca_detail', models.ForeignKey(related_name='ee_certificates', to='rpkidb.CADetail')),
            ],
        ),
        migrations.CreateModel(
            name='Ghostbuster',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('vcard', models.TextField()),
                ('cert', rpki.fields.CertificateField()),
                ('ghostbuster', rpki.fields.GhostbusterField()),
                ('published', rpki.fields.SundialField(null=True)),
                ('ca_detail', models.ForeignKey(related_name='ghostbusters', to='rpkidb.CADetail')),
            ],
        ),
        migrations.CreateModel(
            name='Parent',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('parent_handle', models.SlugField(max_length=255)),
                ('bpki_cert', rpki.fields.CertificateField(null=True)),
                ('bpki_glue', rpki.fields.CertificateField(null=True)),
                ('peer_contact_uri', models.TextField(null=True)),
                ('sia_base', models.TextField(null=True)),
                ('sender_name', models.TextField(null=True)),
                ('recipient_name', models.TextField(null=True)),
                ('last_cms_timestamp', rpki.fields.SundialField(null=True)),
                ('bsc', models.ForeignKey(related_name='parents', to='rpkidb.BSC')),
            ],
        ),
        migrations.CreateModel(
            name='Repository',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('repository_handle', models.SlugField(max_length=255)),
                ('peer_contact_uri', models.TextField(null=True)),
                ('rrdp_notification_uri', models.TextField(null=True)),
                ('bpki_cert', rpki.fields.CertificateField(null=True)),
                ('bpki_glue', rpki.fields.CertificateField(null=True)),
                ('last_cms_timestamp', rpki.fields.SundialField(null=True)),
                ('bsc', models.ForeignKey(related_name='repositories', to='rpkidb.BSC')),
            ],
        ),
        migrations.CreateModel(
            name='RevokedCert',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('serial', models.BigIntegerField()),
                ('revoked', rpki.fields.SundialField()),
                ('expires', rpki.fields.SundialField()),
                ('ca_detail', models.ForeignKey(related_name='revoked_certs', to='rpkidb.CADetail')),
            ],
        ),
        migrations.CreateModel(
            name='ROA',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('asn', models.BigIntegerField()),
                ('ipv4', models.TextField(null=True)),
                ('ipv6', models.TextField(null=True)),
                ('cert', rpki.fields.CertificateField()),
                ('roa', rpki.fields.ROAField()),
                ('published', rpki.fields.SundialField(null=True)),
                ('ca_detail', models.ForeignKey(related_name='roas', to='rpkidb.CADetail')),
            ],
        ),
        migrations.CreateModel(
            name='Tenant',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('tenant_handle', models.SlugField(max_length=255)),
                ('use_hsm', models.BooleanField(default=False)),
                ('crl_interval', models.BigIntegerField(null=True)),
                ('regen_margin', models.BigIntegerField(null=True)),
                ('bpki_cert', rpki.fields.CertificateField(null=True)),
                ('bpki_glue', rpki.fields.CertificateField(null=True)),
            ],
        ),
        migrations.AddField(
            model_name='roa',
            name='tenant',
            field=models.ForeignKey(related_name='roas', to='rpkidb.Tenant'),
        ),
        migrations.AddField(
            model_name='repository',
            name='tenant',
            field=models.ForeignKey(related_name='repositories', to='rpkidb.Tenant'),
        ),
        migrations.AddField(
            model_name='parent',
            name='repository',
            field=models.ForeignKey(related_name='parents', to='rpkidb.Repository'),
        ),
        migrations.AddField(
            model_name='parent',
            name='tenant',
            field=models.ForeignKey(related_name='parents', to='rpkidb.Tenant'),
        ),
        migrations.AddField(
            model_name='ghostbuster',
            name='tenant',
            field=models.ForeignKey(related_name='ghostbusters', to='rpkidb.Tenant'),
        ),
        migrations.AddField(
            model_name='eecertificate',
            name='tenant',
            field=models.ForeignKey(related_name='ee_certificates', to='rpkidb.Tenant'),
        ),
        migrations.AddField(
            model_name='child',
            name='tenant',
            field=models.ForeignKey(related_name='children', to='rpkidb.Tenant'),
        ),
        migrations.AddField(
            model_name='ca',
            name='parent',
            field=models.ForeignKey(related_name='cas', to='rpkidb.Parent'),
        ),
        migrations.AddField(
            model_name='bsc',
            name='tenant',
            field=models.ForeignKey(related_name='bscs', to='rpkidb.Tenant'),
        ),
        migrations.AlterUniqueTogether(
            name='repository',
            unique_together=set([('tenant', 'repository_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='parent',
            unique_together=set([('tenant', 'parent_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='child',
            unique_together=set([('tenant', 'child_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='bsc',
            unique_together=set([('tenant', 'bsc_handle')]),
        ),
    ]
