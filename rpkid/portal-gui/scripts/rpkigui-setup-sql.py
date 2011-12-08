# $Id$
#
# This script is responsible for creating the database used by the
# portal gui.  Look in the settings.py file for the user and password.
# n.b. The configure script generates a random password.
#

import getpass, MySQLdb
from django.conf import settings

dbname = settings.DATABASES['default']['NAME']
dbuser = settings.DATABASES['default']['USER']
dbpass = settings.DATABASES['default']['PASSWORD']

print """WARNING!!!
WARNING!!!
WARNING!!!

About to destroy and recreate the database named "%s" and give access
to the user named "%s".
""" % (dbname, dbuser)

passwd = getpass.getpass('Please enter your MySQL root password: ')

db = MySQLdb.connect(user='root', passwd=passwd)
c = db.cursor()
c.execute('DROP DATABASE IF EXISTS %s' % dbname)
c.execute('CREATE DATABASE %s CHARACTER SET utf8' % dbname)
c.execute('GRANT ALL ON %s.* TO %s@localhost identified by %%s' % (dbname, dbuser), (dbpass,))
