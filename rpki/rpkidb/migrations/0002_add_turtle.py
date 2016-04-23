# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Turtle',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('repository', models.ForeignKey(related_name='parents', to='rpkidb.Repository')),
                ('tenant', models.ForeignKey(related_name='parents', to='rpkidb.Tenant')),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='parent',
            unique_together=set([]),
        ),
        migrations.RemoveField(
            model_name='parent',
            name='id',
        ),
        migrations.RenameField(
            model_name='parent',
            old_name='repository',
            new_name='old_repository',
        ),
        migrations.RenameField(
            model_name='parent',
            old_name='tenant',
            new_name='old_tenant',
        ),
        migrations.AddField(
            model_name='parent',
            name='turtle_ptr',
            field=models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, default=0, serialize=False, to='rpkidb.Turtle'),
            preserve_default=False,
        ),
    ]
