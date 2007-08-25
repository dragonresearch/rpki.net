# $Id$

import rpki.config, rpki.https

msg = "This is a test.  This is only a test.  Had this been real you would now be really confused.\n"

cfg = rpki.config.parser("http-demo.conf")
section = "client"

privateKey = rpki.x509.RSA_Keypair(PEM_file = cfg.get(section, "https-key"))

certChain = rpki.x509.X509_chain()
certChain.load_from_PEM(cfg.multiget(section, "https-cert"))

x509TrustList = rpki.x509.X509_chain()
x509TrustList.load_from_PEM(cfg.multiget(section, "https-ta"))

print rpki.https.client(privateKey=privateKey, certChain=certChain, x509TrustList=x509TrustList, msg=msg)
