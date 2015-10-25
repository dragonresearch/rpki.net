# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pubdb', '0002_auto_20151023_2151'),
    ]

    operations = [
        migrations.AlterField(
            model_name='publishedobject',
            name='der',
            field=models.BinaryField(),
        ),
    ]
