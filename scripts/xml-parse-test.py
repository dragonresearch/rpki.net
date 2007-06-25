# $Id$

import os

def run(func, arg, *cmd):
  i, o = func(cmd)
  i.write(arg)
  i.close()
  value = o.read()
  o.close()
  return value

def relaxng(xml, rng):
  return run(os.popen4, xml, "xmllint", "--noout", "--relaxng", rng, "-")

class rpki_updown_msg(object):
  def toXml(self):
    return ('''<?xml version="1.0" encoding="UTF-8"?>
              <message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
                       version="1"
                       sender="%s"
                       recipient="%s"
                       msg_ref="%d"
                       type="%s">\n''' % (self.sender, self.recipient, self.msg_ref, self.type)
           ) + self.innerToXml() + '</message>\n'

class rpki_updown_err(rpki_updown_msg):
  def innerToXml(self):
    return '<status>%d</status>\n' % self.status

class rpki_updown_list(rpki_updown_msg):
  def innerToXml(self):
    return ""

class rpki_updown_list_response(rpki_updown_msg):
  def innerToXml(self):
    pass

class rpki_updown_issue(rpki_updown_msg):
  def __init__(self):
    self.req_as = None
    self_req_ipv4 = None
    self.req_ipv6 = None
  def innerToXml(self):
    xml = '  <request class_name="%s"' % self.class_name
    if self.req_as != None:
      xml += '\n           req_resource_set_as="%s"' % self.req_as.toXml()
    if self.req_ipv4 != None:
      xml += '\n           req_resource_set_ipv4="%s"' % self.req_ipv4.toXml()
    if self.req_ipv6 != None:
      xml += '\n           req_resource_set_ipv6="%s"' % self.req_ipv6.toXml()
    return xml + self.pkcs10.toXml() + '  </request>\n'

class rpki_issue_response(rpki_updown_msg):
  pass



def main():
  for x in xml:
    print x
    print relaxng(x, "up-down-medium-schema.rng")
    print "=====\n"

# Ugly inline stuff here for initial testing

xml = [
'''<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="error_response">
    <status>2001</status>
    <last_msg_processed>17</last_msg_processed>
    <description xml:lang="en-US">[Readable text]</description>
</message>
''',
'''<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42" type="issue">
    <request class_name="class name"
             req_resource_set_as=""
	     req_resource_set_ipv4="10.0.0.44/32"
	     req_resource_set_ipv6="dead:beef::/32">
        deadbeef
    </request>
</message>
''',
'''<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="1"
	 type="issue_response">
    <class class_name="class name"
           cert_url="url"
	   cert_ski="g(ski)"
	   resource_set_as="22,42,44444-5555555"
	   resource_set_ipv4="10.0.0.44-10.3.0.44,10.6.0.2/32"
	   resource_set_ipv6="dead:beef::/128">
        <certificate cert_url="url"
	             cert_ski="g(ski)"
		     cert_aki="g(aki)"
		     cert_serial="1"
		     resource_set_as="14-17"
		     resource_set_ipv4="128.224.1.136/22"
		     resource_set_ipv6="0:0::/22"
		     req_resource_set_as=""
		     req_resource_set_ipv4="10.0.0.77/16,127.0.0.1/8"
		     req_resource_set_ipv6="dead:beef::/16"
		     status="match">
            deadbeef
        </certificate>
        <issuer>deadbeef</issuer>
    </class>
</message>
''',
'''<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="list"/>
''',
'''<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="list_response">
    <class class_name="class name"
           cert_url="url"
	   cert_ski="g(ski)"
	   resource_set_as="1,2,4,6,16-32"
	   resource_set_ipv4="128.224.1.1-128.22.4.32"
	   resource_set_ipv6=""
	   suggested_sia_head="rsync://wombat.example/fnord/">
        <certificate cert_url="url"
	             cert_ski="g(ski)"
		     cert_aki="g(aki)"
		     cert_serial="1"
		     resource_set_as=""
		     resource_set_ipv4=""
		     resource_set_ipv6=""
		     req_resource_set_as=""
		     req_resource_set_ipv4=""
		     req_resource_set_ipv6=""
		     status="match">
            deadbeef
        </certificate>
        <!-- Repeated for each current certificate naming the client as subject -->
        <issuer>deadbeef</issuer>
    </class>
</message>
''',
'''<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/" 
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="revoke">
    <key class_name="class name"
         ski="g(ski)"/>
</message>
''',
'''<?xml version="1.0" encoding="UTF-8"?>
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"
         version="1"
	 sender="sender name"
	 recipient="recipient name"
	 msg_ref="42"
	 type="revoke_response">
    <key class_name="class name"
         ski="g(ski)"/>
</message>
'''
]

main()
