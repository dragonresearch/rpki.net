#!/bin/bash

export PYTHONPATH=$PWD:$(dirname $PWD)
export DJANGO_SETTINGS_MODULE=settings
django-admin.py $*
