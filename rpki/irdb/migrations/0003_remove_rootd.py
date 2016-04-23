# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('irdb', '0002_root'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='rootd',
            name='issuer',
        ),
        migrations.RemoveField(
            model_name='rootd',
            name='turtle_ptr',
        ),
        migrations.DeleteModel(
            name='Rootd',
        ),
    ]
