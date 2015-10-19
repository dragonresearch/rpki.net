# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0005_auto_20151018_1613'),
    ]

    operations = [
        migrations.AlterField(
            model_name='eecertificate',
            name='ca_detail',
            field=models.ForeignKey(related_name='ee_certificates', to='rpkidb.CADetail'),
        ),
        migrations.AlterField(
            model_name='eecertificate',
            name='self',
            field=models.ForeignKey(related_name='ee_certificates', to='rpkidb.Self'),
        ),
    ]
