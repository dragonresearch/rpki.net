
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


INSERT INTO registrant (IRBE_mapped_id) VALUES ('ARIN');
INSERT INTO registrant (IRBE_mapped_id) VALUES ('TIER1_ISP1');
INSERT INTO registrant (IRBE_mapped_id) VALUES ('TIER1_ISP2');
INSERT INTO registrant (IRBE_mapped_id) VALUES ('JOES_PIZZA');

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'All ARIN resources', '2099-12-31', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'ARIN';

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'Tier 1 ISP foo subject name', '2008-12-31', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'TIER1_ISP1';

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'Tier 1 ISP foo subject name', '2009-06-30', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'TIER1_ISP1';

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'Tier 1 ISP bar subject name', '2007-07-31', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'TIER1_ISP2';

INSERT INTO resource_class (subject_name, valid_until, registrant_id)
SELECT 'arbitrary characters', '2007-12-31', registrant_id
FROM registrant WHERE IRBE_mapped_id = 'JOES_PIZZA';

INSERT INTO net (start_ip, end_ip, version, resource_class_id)
SELECT 'DEAD:BEEF:0000:0000:0000:0000:0000:0000', 'DFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 6, resource_class_id
FROM resource_class WHERE subject_name = 'All ARIN resources';

INSERT INTO net (start_ip, end_ip, version, resource_class_id)
SELECT 'DEAD:BEEF:FACE:0000:0000:0000:0000:0000', 'DEAD:BEEF:FACE:FFFF:FFFF:FFFF:FFFF:FFFF', 6, resource_class_id
FROM resource_class WHERE subject_name = 'TIER 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO net (start_ip, end_ip, version, resource_class_id)
SELECT 'DEAD:BEEF:FACE:FADE:0000:0000:0000:0000', 'DEAD:BEEF:FACE:FADE:FFFF:FFFF:FFFF:FFFF', 6, resource_class_id
FROM resource_class WHERE subject_name = 'arbitrary characters' AND valid_until = '2007-12-31';

INSERT INTO net(start_ip, end_ip, version, resource_class_id)
SELECT '010.000.000.000', '010.255.255.255', 4, resource_class_id
FROM resource_class WHERE subject_name = 'All ARIN resources';

INSERT INTO net(start_ip, end_ip, version, resource_class_id)
SELECT '010.128.000.000', '010.191.255.255', 4, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO net(start_ip, end_ip, version, resource_class_id)
SELECT '010.000.000.000', '010.063.255.255', 4, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO net(start_ip, end_ip, version, resource_class_id)
SELECT '010.128.000.000', '010.191.255.255', 4, resource_class_id
FROM resource_class WHERE subject_name = 'arbitrary characters';

INSERT INTO asn(start_as, end_as, resource_class_id)
SELECT 12345, 12345, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO asn(start_as, end_as, resource_class_id)
SELECT 23456, 23457, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2009-06-30';

INSERT INTO asn(start_as, end_as, resource_class_id)
SELECT 34567, 34567, resource_class_id
FROM resource_class WHERE subject_name = 'Tier 1 ISP foo subject name' AND valid_until = '2008-12-31';
