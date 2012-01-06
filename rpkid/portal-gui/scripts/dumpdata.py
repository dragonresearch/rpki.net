#!/usr/bin/env python
# $Id$
#
# Copyright (C) 2012  SPARTA, Inc. a Parsons Company
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# This is a helper script which will dump the rpki.gui.app models from
# the old sqlite3 database, forcing the output order to the primary key in
# order to avoid forward references for the AddressRange table.

from django.conf import settings
settings.configure(DEBUG=True,
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': '/usr/local/var/rpki/gui.db',
                }
            })

from django.core import serializers
import django.db.models

from rpki.gui.app import models

data = []
for v in (models.Conf, models.Parent, models.Child, models.AddressRange, models.Asn, models.ResourceCert, models.Roa, models.RoaRequest, models.Ghostbuster):
    data.extend(list(v.objects.all().order_by('id')))

print serializers.serialize('json', data, use_natural_keys=True)

# vim:sw=4 ts=8 expandtab
