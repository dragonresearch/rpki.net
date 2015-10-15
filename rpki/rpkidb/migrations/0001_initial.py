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
                ('private_key_id', rpki.fields.KeyField(default=None, serialize=False, blank=True)),
                ('pkcs10_request', rpki.fields.PKCS10Field(default=None, serialize=False, blank=True)),
                ('hash_alg', rpki.fields.EnumField(choices=[(1, 'sha256')])),
                ('signing_cert', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('signing_cert_crl', rpki.fields.CRLField(default=None, serialize=False, null=True, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='CA',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('last_crl_sn', models.BigIntegerField(default=1)),
                ('last_manifest_sn', models.BigIntegerField(default=1)),
                ('next_manifest_update', rpki.fields.SundialField(null=True)),
                ('next_crl_update', rpki.fields.SundialField(null=True)),
                ('last_issued_sn', models.BigIntegerField(default=1)),
                ('sia_uri', models.TextField(null=True)),
                ('parent_resource_class', models.TextField(null=True)),
            ],
        ),
        migrations.CreateModel(
            name='CADetail',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('public_key', rpki.fields.KeyField(default=None, serialize=False, null=True, blank=True)),
                ('private_key_id', rpki.fields.KeyField(default=None, serialize=False, null=True, blank=True)),
                ('latest_crl', rpki.fields.CRLField(default=None, serialize=False, null=True, blank=True)),
                ('crl_published', rpki.fields.SundialField(null=True)),
                ('latest_ca_cert', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('manifest_private_key_id', rpki.fields.KeyField(default=None, serialize=False, null=True, blank=True)),
                ('manifest_public_key', rpki.fields.KeyField(default=None, serialize=False, null=True, blank=True)),
                ('latest_manifest_cert', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('latest_manifest', rpki.fields.ManifestField(default=None, serialize=False, null=True, blank=True)),
                ('manifest_published', rpki.fields.SundialField(null=True)),
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
                ('bpki_cert', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('bpki_glue', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('last_cms_timestamp', rpki.fields.SundialField(null=True)),
                ('bsc', models.ForeignKey(related_name='children', to='rpkidb.BSC')),
            ],
        ),
        migrations.CreateModel(
            name='ChildCert',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('cert', rpki.fields.CertificateField(default=None, serialize=False, blank=True)),
                ('published', rpki.fields.SundialField(null=True)),
                ('ski', rpki.fields.BlobField(default=None, serialize=False, blank=True)),
                ('ca_detail', models.ForeignKey(related_name='child_certs', to='rpkidb.CADetail')),
                ('child', models.ForeignKey(related_name='child_certs', to='rpkidb.Child')),
            ],
        ),
        migrations.CreateModel(
            name='EECert',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('ski', rpki.fields.BlobField(default=None, serialize=False, blank=True)),
                ('cert', rpki.fields.CertificateField(default=None, serialize=False, blank=True)),
                ('published', rpki.fields.SundialField(null=True)),
                ('ca_detail', models.ForeignKey(related_name='ee_certs', to='rpkidb.CADetail')),
            ],
        ),
        migrations.CreateModel(
            name='Ghostbuster',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('vcard', models.TextField()),
                ('cert', rpki.fields.CertificateField(default=None, serialize=False, blank=True)),
                ('ghostbuster', rpki.fields.GhostbusterField(default=None, serialize=False, blank=True)),
                ('published', rpki.fields.SundialField(null=True)),
                ('ca_detail', models.ForeignKey(related_name='ghostbusters', to='rpkidb.CADetail')),
            ],
        ),
        migrations.CreateModel(
            name='Parent',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('parent_handle', models.SlugField(max_length=255)),
                ('bpki_cms_cert', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('bpki_cms_glue', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
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
                ('bpki_cert', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('bpki_glue', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
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
                ('cert', rpki.fields.CertificateField(default=None, serialize=False, blank=True)),
                ('roa', rpki.fields.ROAField(default=None, serialize=False, blank=True)),
                ('published', rpki.fields.SundialField(null=True)),
                ('ca_detail', models.ForeignKey(related_name='roas', to='rpkidb.CADetail')),
            ],
        ),
        migrations.CreateModel(
            name='Self',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('self_handle', models.SlugField(max_length=255)),
                ('use_hsm', models.BooleanField(default=False)),
                ('crl_interval', models.BigIntegerField(null=True)),
                ('regen_margin', models.BigIntegerField(null=True)),
                ('bpki_cert', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
                ('bpki_glue', rpki.fields.CertificateField(default=None, serialize=False, null=True, blank=True)),
            ],
        ),
        migrations.AddField(
            model_name='roa',
            name='self',
            field=models.ForeignKey(related_name='roas', to='rpkidb.Self'),
        ),
        migrations.AddField(
            model_name='repository',
            name='self',
            field=models.ForeignKey(related_name='repositories', to='rpkidb.Self'),
        ),
        migrations.AddField(
            model_name='parent',
            name='repository',
            field=models.ForeignKey(related_name='parents', to='rpkidb.Repository'),
        ),
        migrations.AddField(
            model_name='parent',
            name='self',
            field=models.ForeignKey(related_name='parents', to='rpkidb.Self'),
        ),
        migrations.AddField(
            model_name='ghostbuster',
            name='self',
            field=models.ForeignKey(related_name='ghostbusters', to='rpkidb.Self'),
        ),
        migrations.AddField(
            model_name='eecert',
            name='self',
            field=models.ForeignKey(related_name='ee_certs', to='rpkidb.Self'),
        ),
        migrations.AddField(
            model_name='child',
            name='self',
            field=models.ForeignKey(related_name='children', to='rpkidb.Self'),
        ),
        migrations.AddField(
            model_name='ca',
            name='parent',
            field=models.ForeignKey(related_name='cas', to='rpkidb.Parent'),
        ),
        migrations.AddField(
            model_name='bsc',
            name='self',
            field=models.ForeignKey(related_name='bscs', to='rpkidb.Self'),
        ),
        migrations.AlterUniqueTogether(
            name='repository',
            unique_together=set([('self', 'repository_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='parent',
            unique_together=set([('self', 'parent_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='child',
            unique_together=set([('self', 'child_handle')]),
        ),
        migrations.AlterUniqueTogether(
            name='bsc',
            unique_together=set([('self', 'bsc_handle')]),
        ),
    ]
