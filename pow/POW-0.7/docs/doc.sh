#!/usr/bin/ksh

PACKAGE="POW"
MODULES="POW POW.pkix"

./doc.py ${MODULES}
if [[ $? == 0 ]]
then
   openjade -t tex -d POW_pdf.dsl ${PACKAGE}.sgm
   pdfjadetex ${PACKAGE}.tex
else
   print 'error producing SGML file'
fi
