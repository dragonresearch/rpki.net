# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import rpki.irdb.models
import rpki.fields


class Migration(migrations.Migration):

    dependencies = [
        ('irdb', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Root',
            fields=[
                ('turtle_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to='irdb.Turtle')),
                ('certificate', rpki.fields.CertificateField()),
                ('handle', rpki.irdb.models.HandleField(max_length=120)),
                ('ta', rpki.fields.CertificateField()),
                ('asn_resources', models.TextField()),
                ('ipv4_resources', models.TextField()),
                ('ipv6_resources', models.TextField()),
                ('issuer', models.OneToOneField(related_name='root', to='irdb.ResourceHolderCA')),
            ],
            bases=('irdb.turtle', models.Model),
        ),
        migrations.AlterUniqueTogether(
            name='root',
            unique_together=set([('issuer', 'handle')]),
        ),
    ]
