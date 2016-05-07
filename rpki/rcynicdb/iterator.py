# Copyright (C) 2015--2016  Parsons Government Services ("PARSONS")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
# PARSONS BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
rcynic database iterator.

At least for the moment, we attempt to provide an iterator that works
with both old-style (directory tree of file objects with names similar
to what wget would use) and new style (Django ORM) databases.
"""

import os

initialized_django = False

def _uri_to_class(uri, class_map):
    return class_map[uri[uri.rindex(".")+1:]]

def authenticated_objects(directory_tree = None, uri_suffix = None, class_map = None):

    if class_map is None:
        import rpki.POW
        class_map = dict(cer = rpki.POW.X509,
                         crl = rpki.POW.CRL,
                         gbr = rpki.POW.CMS,
                         mft = rpki.POW.Manifest,
                         roa = rpki.POW.ROA)

    if directory_tree:
        for head, dirs, files in os.walk(directory_tree):
            for fn in files:
                if uri_suffix is None or fn.endswith(uri_suffix):
                    fn = os.path.join(head, fn)
                    uri = "rsync://" + fn[len(directory_tree):].lstrip("/")
                    yield uri, _uri_to_class(uri, class_map).derReadFile(fn)
        return

    global initialized_django
    if not initialized_django:
        os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.rcynic")
        import django
        django.setup()
        initialized_django = True

    import rpki.rcynicdb
    auth = rpki.rcynicdb.models.Authenticated.objects.order_by("-started").first()
    if auth is None:
        return
    
    q = auth.rpkiobject_set
    for obj in q.filter(uri__endswith = uri_suffix) if uri_suffix else q.all():
        yield obj.uri, _uri_to_class(obj.uri, class_map).derRead(obj.der)
