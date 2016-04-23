# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0005_turtle_rehome'),
    ]

    operations = [
        migrations.RenameField(
            model_name='ca',
            old_name='parent',
            new_name='turtle',
        ),
    ]
