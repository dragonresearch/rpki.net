# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


def turtle_forward(apps, schema_editor):
    Turtle = apps.get_model("rpkidb", "Turtle")
    Parent = apps.get_model("rpkidb", "Parent")
    db_alias = schema_editor.connection.alias
    for parent in Parent.objects.using(db_alias).all():
        turtle = Turtle.objects.using(db_alias).create(
            parent_handle = parent.old_parent_handle,
            tenant        = parent.old_tenant,
            repository    = parent.old_repository)
        parent.turtle_ptr = turtle
        parent.save()


def turtle_reverse(apps, schema_editor):
    Turtle = apps.get_model("rpkidb", "Turtle")
    Parent = apps.get_model("rpkidb", "Parent")
    db_alias = schema_editor.connection.alias
    for parent in Parent.objects.using(db_alias).all():
        parent.old_parent_handle = parent.turtle_ptr.parent_handle
        parent.old_tenant        = parent.turtle_ptr.tenant
        parent.old_repository    = parent.turtle_ptr.repository
        parent.turtle_ptr        = None
        parent.save()
    Turtle.objects.using(db_alias).all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ('rpkidb', '0002_add_turtle'),
    ]

    operations = [
        migrations.RunPython(turtle_forward, turtle_reverse)
    ]
