-- $Id$

-- Copyright (C) 2007-2008  American Registry for Internet Numbers ("ARIN")
--
-- Permission to use, copy, modify, and distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
-- REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
-- AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
-- INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
-- LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
-- OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
-- PERFORMANCE OF THIS SOFTWARE.

-- SQL objects needed by the RPKI engine (rpkid.py).

DROP TABLE IF EXISTS self;

CREATE TABLE self (
        self_id                 SERIAL NOT NULL,
        self_handle             VARCHAR(255) NOT NULL,
        use_hsm                 BOOLEAN,
        crl_interval            BIGINT unsigned,
        regen_margin            BIGINT unsigned,
        bpki_cert               LONGBLOB,
        bpki_glue               LONGBLOB,
        PRIMARY KEY             (self_id),
        UNIQUE                  (self_handle)
);

DROP TABLE IF EXISTS bsc;

CREATE TABLE bsc (
        bsc_id                  SERIAL NOT NULL,
        bsc_handle              VARCHAR(255) NOT NULL,
        private_key_id          LONGBLOB,
        pkcs10_request          LONGBLOB,
        hash_alg                ENUM ('sha256'),
        signing_cert            LONGBLOB,
        signing_cert_crl        LONGBLOB,
        self_id                 BIGINT unsigned NOT NULL,
        PRIMARY KEY             (bsc_id),
        FOREIGN KEY             (self_id) REFERENCES self,
        UNIQUE                  (self_id, bsc_handle)
);

DROP TABLE IF EXISTS repository;

CREATE TABLE repository (
        repository_id           SERIAL NOT NULL,
        repository_handle       VARCHAR(255) NOT NULL,
        peer_contact_uri        TEXT,
        bpki_cms_cert           LONGBLOB,
        bpki_cms_glue           LONGBLOB,
        bpki_https_cert         LONGBLOB,
        bpki_https_glue         LONGBLOB,
        bsc_id                  BIGINT unsigned NOT NULL,
        self_id                 BIGINT unsigned NOT NULL,
        PRIMARY KEY             (repository_id),
        FOREIGN KEY             (self_id) REFERENCES self,
        FOREIGN KEY             (bsc_id) REFERENCES bsc,
        UNIQUE                  (self_id, repository_handle)
);

DROP TABLE IF EXISTS parent;

CREATE TABLE parent (
        parent_id               SERIAL NOT NULL,
        parent_handle           VARCHAR(255) NOT NULL,
        bpki_cms_cert           LONGBLOB,
        bpki_cms_glue           LONGBLOB,
        bpki_https_cert         LONGBLOB,
        bpki_https_glue         LONGBLOB,
        peer_contact_uri        TEXT,
        sia_base                TEXT,
        sender_name             TEXT,
        recipient_name          TEXT,
        self_id                 BIGINT unsigned NOT NULL,
        bsc_id                  BIGINT unsigned NOT NULL,
        repository_id           BIGINT unsigned NOT NULL,
        PRIMARY KEY             (parent_id),
        FOREIGN KEY             (repository_id) REFERENCES repository,
        FOREIGN KEY             (bsc_id) REFERENCES bsc,
        FOREIGN KEY             (self_id) REFERENCES self,
        UNIQUE                  (self_id, parent_handle)
);

DROP TABLE IF EXISTS ca;

CREATE TABLE ca (
        ca_id                   SERIAL NOT NULL,
        last_crl_sn             BIGINT unsigned NOT NULL,
        last_manifest_sn        BIGINT unsigned NOT NULL,
        next_manifest_update    DATETIME,
        next_crl_update         DATETIME,
        last_issued_sn          BIGINT unsigned NOT NULL,
        sia_uri                 TEXT,
        parent_resource_class   TEXT,
        parent_id               BIGINT unsigned,
        PRIMARY KEY             (ca_id),
        FOREIGN KEY             (parent_id) REFERENCES parent
);

DROP TABLE IF EXISTS ca_detail;

CREATE TABLE ca_detail (
        ca_detail_id            SERIAL NOT NULL,
        public_key              LONGBLOB,
        private_key_id          LONGBLOB,
        latest_crl              LONGBLOB,
        latest_ca_cert          LONGBLOB,
        manifest_private_key_id LONGBLOB,
        manifest_public_key     LONGBLOB,
        latest_manifest_cert    LONGBLOB,
        latest_manifest         LONGBLOB,
        state                   ENUM ('pending', 'active', 'deprecated', 'revoked') NOT NULL,
        ca_cert_uri             TEXT,
        ca_id                   BIGINT unsigned NOT NULL,
        PRIMARY KEY             (ca_detail_id),
        FOREIGN KEY             (ca_id) REFERENCES ca
);

DROP TABLE IF EXISTS child;

CREATE TABLE child (
        child_id                SERIAL NOT NULL,
        child_handle            VARCHAR(255) NOT NULL,
        bpki_cert               LONGBLOB,
        bpki_glue               LONGBLOB,
        self_id                 BIGINT unsigned NOT NULL,
        bsc_id                  BIGINT unsigned NOT NULL,
        PRIMARY KEY             (child_id),
        FOREIGN KEY             (bsc_id) REFERENCES bsc,
        FOREIGN KEY             (self_id) REFERENCES self,
        UNIQUE                  (self_id, child_handle)
);

DROP TABLE IF EXISTS child_cert;

CREATE TABLE child_cert (
        child_cert_id           SERIAL NOT NULL,
        cert                    LONGBLOB NOT NULL,
        ski                     TINYBLOB NOT NULL,
        child_id                BIGINT unsigned NOT NULL,
        ca_detail_id            BIGINT unsigned NOT NULL,
        PRIMARY KEY             (child_cert_id),
        FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail,
        FOREIGN KEY             (child_id) REFERENCES child
);

DROP TABLE IF EXISTS revoked_cert;

CREATE TABLE revoked_cert (
        revoked_cert_id         SERIAL NOT NULL,
        serial                  BIGINT unsigned NOT NULL,
        revoked                 DATETIME NOT NULL,
        expires                 DATETIME NOT NULL,
        ca_detail_id            BIGINT unsigned NOT NULL,
        PRIMARY KEY             (revoked_cert_id),
        FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail
);

DROP TABLE IF EXISTS route_origin;

CREATE TABLE route_origin (
        route_origin_id         SERIAL NOT NULL,
        route_origin_handle     VARCHAR(255) NOT NULL,
        as_number               DECIMAL(24,0),
        cert                    LONGBLOB,
        roa                     LONGBLOB,
        self_id                 BIGINT unsigned NOT NULL,
        ca_detail_id            BIGINT unsigned,
        PRIMARY KEY             (route_origin_id),
        FOREIGN KEY             (self_id) REFERENCES self,
        FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail,
        UNIQUE                  (self_id, route_origin_handle)
);

DROP TABLE IF EXISTS route_origin_prefix;

CREATE TABLE route_origin_prefix (
        address                 VARCHAR(40) NOT NULL,
        prefixlen               TINYINT NOT NULL,
        max_prefixlen           TINYINT NOT NULL,
        route_origin_id         BIGINT unsigned NOT NULL,
        PRIMARY KEY             (route_origin_id, address, prefixlen, max_prefixlen),
        FOREIGN KEY             (route_origin_id) REFERENCES route_origin
);

-- Local Variables:
-- indent-tabs-mode: nil
-- End:
