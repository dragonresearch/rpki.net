# $Id$

import rpki.https

certInfo = rpki.https.CertInfo("Dave")
print rpki.https.client(certInfo=certInfo, msg="This is a test.  This is only a test.  Had this been real you would now be really confused.\n")
