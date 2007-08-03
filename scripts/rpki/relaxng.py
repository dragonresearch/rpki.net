# $Id$

import lxml.etree

class RelaxNG(lxml.etree.RelaxNG):
  """
  Minor customizations of lxml.etreeRelaxNG.
  """

  def __init__(self, filename):
    """
    Initialize a RelaxNG validator from a file.
    """
    lxml.etree.RelaxNG.__init__(self, lxml.etree.parse(filename))
      
  def assertValid(self, doc):
    """
    Provide a bit more information on validation failures.
    """
    try:
      lxml.etree.RelaxNG.assertValid(self, doc)
    except lxml.etree.DocumentInvalid:
      print self.error_log.last_error
      raise
