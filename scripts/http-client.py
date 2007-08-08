# $Id$

import httplib

http = httplib.HTTPSConnection("localhost", 8080)

http.connect()
http.request("POST", "/", "This is a test.  This is only a test.  Had this been real you would now be really confused.\n", {"Content-Type":"application/wombat"})
response = http.getresponse()

for h in response.getheaders():
  print "%s: %s" % h
print
if response.status == httplib.OK:
  print "OK"
else:
  print "Ouch"
print
print response.read()
