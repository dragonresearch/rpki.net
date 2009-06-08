-- $Id$
--
-- Run this manually under the MySQL CLI to set up databases for testdb.py.
-- testdb.py doesn't do this automatically because it requires privileges
-- that testbed.py doesn't (or at least shouldn't) have.

CREATE DATABASE irdb0;
CREATE DATABASE irdb1;
CREATE DATABASE irdb2;
CREATE DATABASE irdb3;
CREATE DATABASE irdb4;
CREATE DATABASE irdb5;
CREATE DATABASE irdb6;
CREATE DATABASE irdb7;
CREATE DATABASE irdb8;
CREATE DATABASE irdb9;
CREATE DATABASE irdb10;
CREATE DATABASE irdb11;

CREATE DATABASE rpki0;
CREATE DATABASE rpki1;
CREATE DATABASE rpki2;
CREATE DATABASE rpki3;
CREATE DATABASE rpki4;
CREATE DATABASE rpki5;
CREATE DATABASE rpki6;
CREATE DATABASE rpki7;
CREATE DATABASE rpki8;
CREATE DATABASE rpki9;
CREATE DATABASE rpki10;
CREATE DATABASE rpki11;

CREATE DATABASE pubd;

GRANT ALL ON irdb0.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb1.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb2.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb3.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb4.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb5.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb6.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb7.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb8.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb9.*  TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb10.* TO irdb@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON irdb11.* TO irdb@localhost IDENTIFIED BY 'fnord';

GRANT ALL ON rpki0.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki1.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki2.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki3.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki4.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki5.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki6.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki7.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki8.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki9.*  TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki10.* TO rpki@localhost IDENTIFIED BY 'fnord';
GRANT ALL ON rpki11.* TO rpki@localhost IDENTIFIED BY 'fnord';

GRANT ALL ON pubd.*   TO pubd@localhost IDENTIFIED BY 'fnord';
