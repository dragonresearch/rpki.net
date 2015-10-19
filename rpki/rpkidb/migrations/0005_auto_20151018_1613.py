# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0004_auto_20151018_1602'),
    ]

    operations = [
        migrations.CreateModel(
            name='EECertificate',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('ski', rpki.fields.BlobField(default=None, serialize=False, blank=True)),
                ('cert', rpki.fields.CertificateField(default=None, serialize=False, blank=True)),
                ('published', rpki.fields.SundialField(null=True)),
                ('ca_detail', models.ForeignKey(related_name='ee_certificatess', to='rpkidb.CADetail')),
                ('self', models.ForeignKey(related_name='ee_certificatess', to='rpkidb.Self')),
            ],
        ),
        migrations.RemoveField(
            model_name='eecert',
            name='ca_detail',
        ),
        migrations.RemoveField(
            model_name='eecert',
            name='self',
        ),
        migrations.DeleteModel(
            name='EECert',
        ),
    ]
