drop table if exists bsc;
drop table if exists bsc_cert;
drop table if exists bsc_key;
drop table if exists ca;
drop table if exists ca_detail;
drop table if exists ca_use;
drop table if exists child;
drop table if exists child_ca_detail_link;
drop table if exists ee_cert;
drop table if exists manifest;
drop table if exists manifest_content;
drop table if exists parent;
drop table if exists repos;
drop table if exists roa;
drop table if exists route_origin;
drop table if exists self;
drop table if exists self_pref;
drop table if exists route_origin_prefix;


CREATE TABLE bsc (
       bsc_id               INT unsigned auto_increment NOT NULL,
       self_id              INT unsigned NOT NULL,
       PRIMARY KEY (bsc_id)
);


CREATE TABLE bsc_cert (
       bsc_cert_id          INT unsigned auto_increment NOT NULL,
       request              LONGTEXT,
       cert                 LONGTEXT,
       bsc_key_id           INT unsigned NOT NULL,
       PRIMARY KEY (bsc_cert_id)
);


CREATE TABLE bsc_key (
       bsc_key_id           INT unsigned auto_increment NOT NULL,
       key_type             VARCHAR(100),
       hash_alg             TEXT,
       key_length           INT unsigned,
       pub_key              TEXT,
       priv_key_id          TEXT,
       bsc_id               INT unsigned NOT NULL,
       PRIMARY KEY (bsc_key_id)
);


CREATE TABLE ca (
       ca_id                INT unsigned auto_increment NOT NULL,
       crl                  TEXT,
       last_sn              INT unsigned,
       last_manifest_sn     INT,
       PRIMARY KEY (ca_id)
);


CREATE TABLE ca_detail (
       ca_detail_id         INT unsigned auto_increment NOT NULL,
       pub_key              TEXT,
       priv_key_id          TEXT,
       latest_crl           TEXT,
       latest_ca_cert_over_pubkey LONGTEXT,
       ca_id                INT unsigned NOT NULL,
       PRIMARY KEY (ca_detail_id)
);


CREATE TABLE ca_use (
       ca_id                INT unsigned NOT NULL,
       entity_id            INT unsigned NOT NULL,
       PRIMARY KEY (ca_id, entity_id)
);


CREATE TABLE child (
       child_id             INT unsigned auto_increment NOT NULL,
       ta                   TEXT,
       self_id              INT unsigned NOT NULL,
       bsc_id               INT unsigned NOT NULL,
       PRIMARY KEY (child_id)
);


CREATE TABLE child_ca_detail_link (
       child_id             INT unsigned NOT NULL,
       ca_detail_id         INT unsigned NOT NULL,
       PRIMARY KEY (child_id, ca_detail_id)
);


CREATE TABLE ee_cert (
       ca_detail_id         INT unsigned NOT NULL,
       cert                 LONGTEXT,
       PRIMARY KEY (ca_detail_id)
);


CREATE TABLE manifest (
       manifest_serial_id   INT unsigned auto_increment NOT NULL,
       hash_alg             TEXT,
       this_update          DATETIME,
       next_update          DATETIME,
       self_id              INT unsigned NOT NULL,
       collection_uri       TEXT,
       version              INT,
       PRIMARY KEY (manifest_serial_id)
);


CREATE TABLE manifest_content (
       filename             varchar(65000),
       hash                 TEXT,
       manifest_serial_id   INT unsigned NOT NULL,
       PRIMARY KEY (manifest_serial_id, filename)
);


CREATE TABLE parent (
       parent_id            INT unsigned auto_increment NOT NULL,
       ta                   TEXT,
       url                  TEXT,
       sia_base             TEXT,
       self_id              INT unsigned NOT NULL,
       bsc_id               INT unsigned NOT NULL,
       repos_id             INT unsigned NOT NULL,
       PRIMARY KEY (parent_id)
);


CREATE TABLE repos (
       repos_id             INT unsigned auto_increment NOT NULL,
       uri                  TEXT,
       ta                   TEXT,
       self_id              INT unsigned NOT NULL,
       bsc_id               INT unsigned NOT NULL,
       PRIMARY KEY (repos_id)
);


CREATE TABLE roa (
       ca_detail_id         INT unsigned NOT NULL,
       route_origin_id      INT unsigned NOT NULL,
       PRIMARY KEY (ca_detail_id, route_origin_id)
);


CREATE TABLE route_origin (
       route_origin_id      INT unsigned auto_increment NOT NULL,
       as_number            INT unsigned,
       self_id              INT unsigned NOT NULL,
       PRIMARY KEY (route_origin_id)
);


CREATE TABLE route_origin_prefix (
       start_ip             VARCHAR(40),
       prefix               INT unsigned,
       end_ip               VARCHAR(40),
       version              INT unsigned,
       route_origin_id      INT unsigned NOT NULL,
       PRIMARY KEY (route_origin_id, start_ip, end_ip)
);


CREATE TABLE self (
       self_id              INT unsigned auto_increment NOT NULL,
       PRIMARY KEY (self_id)
);


CREATE TABLE self_pref (
       pref_name            VARCHAR(100),
       pref_value           TEXT,
       self_id              INT unsigned NOT NULL,
       PRIMARY KEY (self_id, pref_name)
);


ALTER TABLE bsc
       ADD FOREIGN KEY (self_id)
                             REFERENCES self;


ALTER TABLE bsc_cert
       ADD FOREIGN KEY (bsc_key_id)
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



