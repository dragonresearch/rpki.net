#
# This is an example wsgi application for use with mod_wsgi and apache.
#

# change this path to match where you have installed the portal-gui source
srcdir = '/home/me/src/rpki'

import os
import sys

os.environ['DJANGO_SETTINGS_MODULE'] = 'rpkigui.settings'

sys.path.append(srcdir+'/portal-gui')
sys.path.append(srcdir+'/portal-gui/myrpki')
sys.path.append(srcdir+'/rpkid')

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()
