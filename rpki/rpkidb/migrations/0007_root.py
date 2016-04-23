# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0006_turtle_rename'),
    ]

    operations = [
        migrations.CreateModel(
            name='Root',
            fields=[
                ('turtle_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='rpkidb.Turtle')),
                ('asn_resources', models.TextField()),
                ('ipv4_resources', models.TextField()),
                ('ipv6_resources', models.TextField()),
                ('worker', models.OneToOneField(related_name='rooter', to='rpkidb.Parent')),
            ],
            bases=('rpkidb.turtle',),
        ),
    ]
