#!/usr/bin/env python

import os
from django.core.management import execute_from_command_line

# django-admin seems to have problems creating the superuser account when
# $LANG is unset
if not 'LANG' in os.environ:
    os.environ['LANG'] = 'en_US.UTF-8'

os.environ['DJANGO_SETTINGS_MODULE'] = 'rpki.gui.default_settings'

execute_from_command_line()
