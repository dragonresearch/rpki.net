#!/bin/sh -
# $Id$

# GRANT ALL ON rpki.* TO rpki@localhost IDENTIFIED BY '<secret>';
# GRANT ALL ON irdb.* TO irdb@localhost IDENTIFIED BY '<secret>';

echo "This script destroys and rebuilds our databases."
echo "Don't type the password unless you're sure you want to do this."

(echo 'DROP DATABASE rpki; CREATE DATABASE rpki; USE rpki;'
 cat ../docs/rpki-db-schema.sql
 echo 'DROP DATABASE irdb; CREATE DATABASE irdb; USE irdb;'
 cat ../docs/sample-irdb.sql
) |
mysql -u root -p
