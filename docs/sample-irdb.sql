-- $Id$

DROP TABLE IF EXISTS registrant;

CREATE TABLE registrant (
       registrant_id        SERIAL NOT NULL,
       IRBE_mapped_id       TEXT,
       subject_name         TEXT,
       valid_until          DATETIME NOT NULL,
       PRIMARY KEY	    (registrant_id)
);

DROP TABLE IF EXISTS asn;

CREATE TABLE asn (
       asn_id               SERIAL NOT NULL,
       start_as             BIGINT unsigned NOT NULL,
       end_as               BIGINT unsigned NOT NULL,
       registrant_id        BIGINT unsigned NOT NULL,
       PRIMARY KEY	    (asn_id),
       FOREIGN KEY          (registrant_id) REFERENCES registrant ON DELETE SET NULL ON UPDATE SET NULL
);

DROP TABLE IF EXISTS net;

CREATE TABLE net (
       net_id               SERIAL NOT NULL,
       start_ip             VARCHAR(40) NOT NULL,
       end_ip               VARCHAR(40) NOT NULL,
       version              TINYINT unsigned NOT NULL,
       registrant_id        BIGINT unsigned NOT NULL,
       PRIMARY KEY          (net_id),
       FOREIGN KEY          (registrant_id) REFERENCES registrant ON DELETE SET NULL ON UPDATE SET NULL
);
