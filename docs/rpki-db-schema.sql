
CREATE TABLE bsc (
       bsc_id               INT unsigned auto_increment NOT NULL,
       self_id              INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKbsc ON bsc
(
       bsc_id
);


ALTER TABLE bsc
       ADD PRIMARY KEY (bsc_id);


CREATE TABLE bsc_cert (
       bsc_cert_id          INT unsigned auto_increment NOT NULL,
       request              LONGBLOB,
       cert                 LONGBLOB,
       bsc_id               INT unsigned NOT NULL,
       bsc_key_id           INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKbsc_cert ON bsc_cert
(
       bsc_id,
       bsc_key_id,
       bsc_cert_id
);


ALTER TABLE bsc_cert
       ADD PRIMARY KEY (bsc_id, bsc_key_id, bsc_cert_id);


CREATE TABLE bsc_key (
       bsc_key_id           INT unsigned auto_increment NOT NULL,
       key_type             VARCHAR(100),
       hash_alg             TEXT,
       key_length           INT unsigned,
       pub_key              LONGBLOB,
       priv_key_id          LONGBLOB,
       bsc_id               INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKbsc_key ON bsc_key
(
       bsc_id,
       bsc_key_id
);


ALTER TABLE bsc_key
       ADD PRIMARY KEY (bsc_id, bsc_key_id);


CREATE TABLE ca (
       ca_id                INT unsigned NOT NULL,
       crl                  LONGBLOB,
       last_sn              INT unsigned,
       last_manifest_sn     INT unsigned
);

CREATE UNIQUE INDEX XPKca ON ca
(
       ca_id
);


ALTER TABLE ca
       ADD PRIMARY KEY (ca_id);


CREATE TABLE ca_detail (
       ca_detail_id         INT unsigned NOT NULL,
       pub_key              LONGBLOB,
       priv_key_id          LONGBLOB,
       latest_crl           LONGBLOB,
       latest_ca_cert_over_pubkey LONGBLOB,
       ca_id                INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKca_detail ON ca_detail
(
       ca_detail_id
);


ALTER TABLE ca_detail
       ADD PRIMARY KEY (ca_detail_id);


CREATE TABLE ca_use (
       ca_id                INT unsigned NOT NULL,
       entity_id            INT unsigned auto_increment NOT NULL
);

CREATE UNIQUE INDEX XPKca_use ON ca_use
(
       ca_id,
       entity_id
);


ALTER TABLE ca_use
       ADD PRIMARY KEY (ca_id, entity_id);


CREATE TABLE child (
       child_id             INT unsigned auto_increment NOT NULL,
       ta                   LONGBLOB,
       self_id              INT unsigned NOT NULL,
       bsc_id               INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKchild ON child
(
       child_id
);


ALTER TABLE child
       ADD PRIMARY KEY (child_id);


CREATE TABLE child_ca_detail_link (
       child_id             INT unsigned NOT NULL,
       ca_detail_id         INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKchild_ca_detail_link ON child_ca_detail_link
(
       child_id,
       ca_detail_id
);


ALTER TABLE child_ca_detail_link
       ADD PRIMARY KEY (child_id, ca_detail_id);


CREATE TABLE ee_cert (
       ca_detail_id         INT unsigned NOT NULL,
       cert                 LONGBLOB
);

CREATE UNIQUE INDEX XPKee_cert ON ee_cert
(
       ca_detail_id
);


ALTER TABLE ee_cert
       ADD PRIMARY KEY (ca_detail_id);


CREATE TABLE manifest (
       manifest_serial_id   INT unsigned auto_increment NOT NULL,
       hash_alg             TEXT,
       this_update          DATETIME,
       next_update          DATETIME,
       self_id              INT unsigned NOT NULL,
       collection_uri       TEXT,
       version              INT unsigned
);

CREATE UNIQUE INDEX XPKmanifest ON manifest
(
       manifest_serial_id
);


ALTER TABLE manifest
       ADD PRIMARY KEY (manifest_serial_id);


CREATE TABLE manifest_content (
       filename             TEXT,
       hash                 TEXT,
       manifest_serial_id   INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKmanifest_content ON manifest_content
(
       manifest_serial_id,
       filename
);


ALTER TABLE manifest_content
       ADD PRIMARY KEY (manifest_serial_id, filename);


CREATE TABLE parent (
       parent_id            INT unsigned auto_increment NOT NULL,
       ta                   LONGBLOB,
       url                  TEXT,
       sia_base             TEXT,
       self_id              INT unsigned NOT NULL,
       bsc_id               INT unsigned NOT NULL,
       repos_id             INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKparent ON parent
(
       parent_id
);


ALTER TABLE parent
       ADD PRIMARY KEY (parent_id);


CREATE TABLE repos (
       repos_id             INT unsigned auto_increment NOT NULL,
       uri                  TEXT,
       ta                   LONGBLOB,
       self_id              INT unsigned NOT NULL,
       bsc_id               INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKrepos ON repos
(
       repos_id
);


ALTER TABLE repos
       ADD PRIMARY KEY (repos_id);


CREATE TABLE roa (
       ca_detail_id         INT unsigned NOT NULL,
       route_origin_id      INT unsigned NOT NULL
);


CREATE TABLE route_origin (
       route_origin_id      INT unsigned auto_increment NOT NULL,
       as_number            DECIMAL,
       self_id              INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKroute_origin ON route_origin
(
       route_origin_id
);


ALTER TABLE route_origin
       ADD PRIMARY KEY (route_origin_id);


CREATE TABLE route_origin_prefix (
       start_ip             VARCHAR(40),
       prefix               INT unsigned,
       end_ip               VARCHAR(40),
       version              INT unsigned,
       route_origin_id      INT unsigned NOT NULL
);


CREATE TABLE self (
       self_id              INT unsigned auto_increment NOT NULL
);

CREATE UNIQUE INDEX XPKself ON self
(
       self_id
);


ALTER TABLE self
       ADD PRIMARY KEY (self_id);


CREATE TABLE self_pref (
       pref_name            VARCHAR(100),
       pref_value           TEXT,
       self_id              INT unsigned NOT NULL
);

CREATE UNIQUE INDEX XPKself_pref ON self_pref
(
       self_id,
       pref_name
);


ALTER TABLE self_pref
       ADD PRIMARY KEY (self_id, pref_name);


ALTER TABLE bsc
       ADD FOREIGN KEY (self_id)
                             REFERENCES self;


ALTER TABLE bsc_cert
       ADD FOREIGN KEY (bsc_id, bsc_key_id)
                             REFERENCES bsc_key;


ALTER TABLE bsc_key
       ADD FOREIGN KEY (bsc_id)
                             REFERENCES bsc;


ALTER TABLE ca_detail
       ADD FOREIGN KEY (ca_id)
                             REFERENCES ca;


ALTER TABLE ca_use
       ADD FOREIGN KEY (ca_id)
                             REFERENCES ca;


ALTER TABLE child
       ADD FOREIGN KEY (bsc_id)
                             REFERENCES bsc;


ALTER TABLE child
       ADD FOREIGN KEY (self_id)
                             REFERENCES self;


ALTER TABLE child_ca_detail_link
       ADD FOREIGN KEY (ca_detail_id)
                             REFERENCES ca_detail;


ALTER TABLE child_ca_detail_link
       ADD FOREIGN KEY (child_id)
                             REFERENCES child;


ALTER TABLE ee_cert
       ADD FOREIGN KEY (ca_detail_id)
                             REFERENCES ca_detail;


ALTER TABLE manifest
       ADD FOREIGN KEY (self_id)
                             REFERENCES self;


ALTER TABLE manifest_content
       ADD FOREIGN KEY (manifest_serial_id)
                             REFERENCES manifest;


ALTER TABLE parent
       ADD FOREIGN KEY (repos_id)
                             REFERENCES repos;


ALTER TABLE parent
       ADD FOREIGN KEY (bsc_id)
                             REFERENCES bsc;


ALTER TABLE parent
       ADD FOREIGN KEY (self_id)
                             REFERENCES self;


ALTER TABLE repos
       ADD FOREIGN KEY (bsc_id)
                             REFERENCES bsc;


ALTER TABLE repos
       ADD FOREIGN KEY (self_id)
                             REFERENCES self;


ALTER TABLE roa
       ADD FOREIGN KEY (route_origin_id)
                             REFERENCES route_origin;


ALTER TABLE roa
       ADD FOREIGN KEY (ca_detail_id)
                             REFERENCES ee_cert;


ALTER TABLE route_origin
       ADD FOREIGN KEY (self_id)
                             REFERENCES self;


ALTER TABLE route_origin_prefix
       ADD FOREIGN KEY (route_origin_id)
                             REFERENCES route_origin;


ALTER TABLE self_pref
       ADD FOREIGN KEY (self_id)
                             REFERENCES self;



