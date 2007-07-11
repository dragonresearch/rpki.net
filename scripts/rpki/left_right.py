# $Id$

import base64, sax_utils, resource_set

class msg(list):
  """
  Left-right PDU.
  """

  spec_uri = "http://www.hactrn.net/uris/rpki/left-right-spec/"
  version = 1

  dispatch = {
    ("control-request",  "biz-signing-context")   : bsc_q,
    ("control-request",  "child")                 : child_q,
    ("control-request",  "parent")                : parent_q,
    ("control-request",  "repository")            : repository_q,
    ("control-request",  "route-origin")          : route_origin_q,
    ("control-request",  "self")                  : self_q,
    ("control-response", "biz-signing-context")   : bsc_r,
    ("control-response", "child")                 : child_r,
    ("control-response", "parent")                : parent_r,
    ("control-response", "repository")            : repository_r,
    ("control-response", "route-origin")          : route_origin_r,
    ("control-response", "self")                  : self_r,
    ("data-request",     "list-resources")        : list_resources_q,
    ("data-response",    "list-resources")        : list_resources_r,
    ("error",            "report-error")          : report_error_q
 }

  def __str__(self):
    return ('\
<?xml version="1.0" encoding="US-ASCII" ?>\n\
<msg xmlns="%s"\n\
         version="%d"\n\
         type="%s">\n' \
            % (self.spec_uri, self.version, self.type)
            ) + "".join(map(str,self)) + "</msg>\n"

  def endElement(self, name, text):
    pass

  def startElement(self, name, attrs):
    if name == "msg":
      sax_utils.snarf(self, attrs, "version", int)
      sax_utils.snarf(self, attrs, "type")
      assert self.version == 1
    else:
      func = self.dispatch(self.type, name)
      # hmm, proabbly want to look at action attribute but that's a
      # layering violation, so maybe do it in the next handler down?

class sax_handler(sax_utils.handler):
  """
  SAX handler for Left-Right protocol.
  """

  def startElement(self, name, attrs):
    if name == "msg":
      self.set_obj(msg())
    self.obj.startElement(name, attrs)

  def endElement(self, name):
    self.obj.endElement(name, self.get_text())
