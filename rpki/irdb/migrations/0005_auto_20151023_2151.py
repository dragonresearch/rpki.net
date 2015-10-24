# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.irdb.models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
        ('irdb', '0004_auto_20151018_1603'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bsc',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='bsc',
            name='pkcs10',
            field=rpki.fields.PKCS10Field(),
        ),
        migrations.AlterField(
            model_name='child',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='child',
            name='ta',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='client',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='client',
            name='ta',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='eecertificaterequest',
            name='pkcs10',
            field=rpki.fields.PKCS10Field(),
        ),
        migrations.AlterField(
            model_name='hostedca',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='parent',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='parent',
            name='referral_authorization',
            field=rpki.irdb.models.SignedReferralField(null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='parent',
            name='ta',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='referral',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='referral',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(),
        ),
        migrations.AlterField(
            model_name='repository',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='repository',
            name='ta',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='resourceholderca',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='resourceholderca',
            name='latest_crl',
            field=rpki.fields.CRLField(),
        ),
        migrations.AlterField(
            model_name='resourceholderca',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(),
        ),
        migrations.AlterField(
            model_name='rootd',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='rootd',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(),
        ),
        migrations.AlterField(
            model_name='serverca',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='serverca',
            name='latest_crl',
            field=rpki.fields.CRLField(),
        ),
        migrations.AlterField(
            model_name='serverca',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(),
        ),
        migrations.AlterField(
            model_name='serveree',
            name='certificate',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='serveree',
            name='private_key',
            field=rpki.fields.RSAPrivateKeyField(),
        ),
    ]
