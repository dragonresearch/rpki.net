
DROP TABLE IF EXISTS asn;
CREATE TABLE asn (
       asn_id               SERIAL NOT NULL,
       start_as             BIGINT unsigned NOT NULL,
       end_as               BIGINT unsigned NOT NULL,
       resource_class_id    BIGINT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKasn ON asn
(
       asn_id
);

ALTER TABLE asn
       ADD PRIMARY KEY (asn_id);

DROP TABLE IF EXISTS net;

CREATE TABLE net (
       net_id               SERIAL NOT NULL,
       start_ip             VARCHAR(40) NOT NULL,
       end_ip               VARCHAR(40) NOT NULL,
       version              TINYINT unsigned NOT NULL,
       resource_class_id    BIGINT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKnet ON net
(
       net_id
);

ALTER TABLE net
       ADD PRIMARY KEY (net_id);


DROP TABLE IF EXISTS registrant;

CREATE TABLE registrant (
       registrant_id        SERIAL NOT NULL,
       IRBE_mapped_id       TEXT
);

CREATE UNIQUE INDEX XPKregistrant ON registrant
(
       registrant_id
);

ALTER TABLE registrant
       ADD PRIMARY KEY (registrant_id);

DROP TABLE IF EXISTS resource_class;

CREATE TABLE resource_class (
       resource_class_id    SERIAL NOT NULL,
       subject_name         TEXT,
       valid_until          DATETIME NOT NULL,
       registrant_id        BIGINT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKresource_class ON resource_class
(
       resource_class_id
);

ALTER TABLE resource_class
       ADD PRIMARY KEY (resource_class_id);

ALTER TABLE asn
       ADD FOREIGN KEY (resource_class_id)
                             REFERENCES resource_class
                             ON DELETE SET NULL
                             ON UPDATE SET NULL;

ALTER TABLE net
       ADD FOREIGN KEY (resource_class_id)
                             REFERENCES resource_class
                             ON DELETE SET NULL
                             ON UPDATE SET NULL;

ALTER TABLE resource_class
       ADD FOREIGN KEY (registrant_id)
                             REFERENCES registrant
                             ON DELETE SET NULL
                             ON UPDATE SET NULL;
