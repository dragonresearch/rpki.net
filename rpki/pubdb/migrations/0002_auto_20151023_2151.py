# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
        ('pubdb', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='client',
            name='bpki_cert',
            field=rpki.fields.CertificateField(),
        ),
        migrations.AlterField(
            model_name='client',
            name='bpki_glue',
            field=rpki.fields.CertificateField(null=True),
        ),
    ]
