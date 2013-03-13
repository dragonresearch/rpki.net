"""
Ensure that a web login exists for labuser* resource holder
"""

import os
import sys

# if the environment is not already set up, look in the default places
if not os.getenv("DJANGO_SETTINGS_MODULE"):
    os.environ["DJANGO_SETTINGS_MODULE"] = 'settings'
    for d in ('/etc/rpki', '/usr/local/etc/rpki'):
        if os.path.exists(os.path.join(d, 'settings.py')):
            print 'found settings.py in ' + d
            sys.path.insert(1, d)
            break

from django.contrib.auth.models import User
from rpki.gui.app.models import Conf, ConfACL

# mysql> select * from irdb_resourceholderca left outer join auth_user on irdb_resourceholderca.handle = auth_user.username where username=NULL;

for conf in Conf.objects.filter(handle__startswith='labuser'):
    if not User.objects.filter(username=conf.handle).exists():
        print 'creating matching user for ' + conf.handle
        user = User.objects.create_user(conf.handle, password='fnord')
        ConfACL.objects.create(conf=conf, user=user)
