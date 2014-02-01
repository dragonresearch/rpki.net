-- $Id$

-- Copyright (C) 2009--2011  Internet Systems Consortium ("ISC")
--
-- Permission to use, copy, modify, and distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
-- REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
-- AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
-- INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
-- LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
-- OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
-- PERFORMANCE OF THIS SOFTWARE.

-- Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
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

-- DROP TABLE commands must be in correct (reverse dependency) order
-- to satisfy FOREIGN KEY constraints.

DROP TABLE IF EXISTS ghostbuster;
DROP TABLE IF EXISTS roa_prefix;
DROP TABLE IF EXISTS roa;
DROP TABLE IF EXISTS revoked_cert;
DROP TABLE IF EXISTS child_cert;
DROP TABLE IF EXISTS child;
DROP TABLE IF EXISTS ca_detail;
DROP TABLE IF EXISTS ca;
DROP TABLE IF EXISTS parent;
DROP TABLE IF EXISTS repository;
DROP TABLE IF EXISTS bsc;
DROP TABLE IF EXISTS self;

CREATE TABLE self (
        self_id                 SERIAL NOT NULL,
        self_handle             VARCHAR(255) NOT NULL,
        use_hsm                 BOOLEAN NOT NULL DEFAULT FALSE,
        crl_interval            BIGINT UNSIGNED,
        regen_margin            BIGINT UNSIGNED,
        bpki_cert               LONGBLOB,
        bpki_glue               LONGBLOB,
        PRIMARY KEY             (self_id),
        UNIQUE                  (self_handle)
) ENGINE=InnoDB;

CREATE TABLE bsc (
        bsc_id                  SERIAL NOT NULL,
        bsc_handle              VARCHAR(255) NOT NULL,
        private_key_id          LONGBLOB,
        pkcs10_request          LONGBLOB,
        hash_alg                ENUM ('sha256'),
        signing_cert            LONGBLOB,
        signing_cert_crl        LONGBLOB,
        self_id                 BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (bsc_id),
        CONSTRAINT              bsc_self_id
        FOREIGN KEY             (self_id) REFERENCES self (self_id) ON DELETE CASCADE,
        UNIQUE                  (self_id, bsc_handle)
) ENGINE=InnoDB;

CREATE TABLE repository (
        repository_id           SERIAL NOT NULL,
        repository_handle       VARCHAR(255) NOT NULL,
        peer_contact_uri        TEXT,
        bpki_cert               LONGBLOB,
        bpki_glue               LONGBLOB,
        last_cms_timestamp      DATETIME,
        bsc_id                  BIGINT UNSIGNED NOT NULL,
        self_id                 BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (repository_id),
        CONSTRAINT              repository_self_id
        FOREIGN KEY             (self_id) REFERENCES self (self_id) ON DELETE CASCADE,
        CONSTRAINT              repository_bsc_id
        FOREIGN KEY             (bsc_id) REFERENCES bsc (bsc_id) ON DELETE CASCADE,
        UNIQUE                  (self_id, repository_handle)
) ENGINE=InnoDB;

CREATE TABLE parent (
        parent_id               SERIAL NOT NULL,
        parent_handle           VARCHAR(255) NOT NULL,
        bpki_cms_cert           LONGBLOB,
        bpki_cms_glue           LONGBLOB,
        peer_contact_uri        TEXT,
        sia_base                TEXT,
        sender_name             TEXT,
        recipient_name          TEXT,
        last_cms_timestamp      DATETIME,
        self_id                 BIGINT UNSIGNED NOT NULL,
        bsc_id                  BIGINT UNSIGNED NOT NULL,
        repository_id           BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (parent_id),
        CONSTRAINT              parent_repository_id
        FOREIGN KEY             (repository_id) REFERENCES repository (repository_id) ON DELETE CASCADE,
        CONSTRAINT              parent_bsc_id
        FOREIGN KEY             (bsc_id) REFERENCES bsc (bsc_id) ON DELETE CASCADE,
        CONSTRAINT              parent_self_id
        FOREIGN KEY             (self_id) REFERENCES self (self_id) ON DELETE CASCADE,
        UNIQUE                  (self_id, parent_handle)
) ENGINE=InnoDB;

CREATE TABLE ca (
        ca_id                   SERIAL NOT NULL,
        last_crl_sn             BIGINT UNSIGNED NOT NULL,
        last_manifest_sn        BIGINT UNSIGNED NOT NULL,
        next_manifest_update    DATETIME,
        next_crl_update         DATETIME,
        last_issued_sn          BIGINT UNSIGNED NOT NULL,
        sia_uri                 TEXT,
        parent_resource_class   TEXT,
        parent_id               BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (ca_id),
        CONSTRAINT              ca_parent_id
        FOREIGN KEY             (parent_id) REFERENCES parent (parent_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE ca_detail (
        ca_detail_id            SERIAL NOT NULL,
        public_key              LONGBLOB,
        private_key_id          LONGBLOB,
        latest_crl              LONGBLOB,
        crl_published           DATETIME,
        latest_ca_cert          LONGBLOB,
        manifest_private_key_id LONGBLOB,
        manifest_public_key     LONGBLOB,
        latest_manifest_cert    LONGBLOB,
        latest_manifest         LONGBLOB,
        manifest_published      DATETIME,
        state                   ENUM ('pending', 'active', 'deprecated', 'revoked') NOT NULL,
        ca_cert_uri             TEXT,
        ca_id                   BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (ca_detail_id),
        CONSTRAINT              ca_detail_ca_id
        FOREIGN KEY             (ca_id) REFERENCES ca (ca_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE child (
        child_id                SERIAL NOT NULL,
        child_handle            VARCHAR(255) NOT NULL,
        bpki_cert               LONGBLOB,
        bpki_glue               LONGBLOB,
        last_cms_timestamp      DATETIME,
        self_id                 BIGINT UNSIGNED NOT NULL,
        bsc_id                  BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (child_id),
        CONSTRAINT              child_bsc_id 
        FOREIGN KEY             (bsc_id) REFERENCES bsc (bsc_id) ON DELETE CASCADE,
        CONSTRAINT              child_self_id
        FOREIGN KEY             (self_id) REFERENCES self (self_id) ON DELETE CASCADE,
        UNIQUE                  (self_id, child_handle)
) ENGINE=InnoDB;

CREATE TABLE child_cert (
        child_cert_id           SERIAL NOT NULL,
        cert                    LONGBLOB NOT NULL,
        published               DATETIME,
        ski                     TINYBLOB NOT NULL,
        child_id                BIGINT UNSIGNED NOT NULL,
        ca_detail_id            BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (child_cert_id),
        CONSTRAINT              child_cert_ca_detail_id
        FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail (ca_detail_id) ON DELETE CASCADE,
        CONSTRAINT              child_cert_child_id
        FOREIGN KEY             (child_id) REFERENCES child (child_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE revoked_cert (
        revoked_cert_id         SERIAL NOT NULL,
        serial                  BIGINT UNSIGNED NOT NULL,
        revoked                 DATETIME NOT NULL,
        expires                 DATETIME NOT NULL,
        ca_detail_id            BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (revoked_cert_id),
        CONSTRAINT              revoked_cert_ca_detail_id
        FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail (ca_detail_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE roa (
        roa_id                  SERIAL NOT NULL,
        asn                     BIGINT UNSIGNED NOT NULL,
        cert                    LONGBLOB NOT NULL,
        roa                     LONGBLOB NOT NULL,
        published               DATETIME,
        self_id                 BIGINT UNSIGNED NOT NULL,
        ca_detail_id            BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (roa_id),
        CONSTRAINT              roa_self_id
        FOREIGN KEY             (self_id) REFERENCES self (self_id) ON DELETE CASCADE,
        CONSTRAINT              roa_ca_detail_id
        FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail (ca_detail_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE roa_prefix (
        prefix                  VARCHAR(40) NOT NULL,
        prefixlen               TINYINT UNSIGNED NOT NULL,
        max_prefixlen           TINYINT UNSIGNED NOT NULL,
        version                 TINYINT UNSIGNED NOT NULL,
        roa_id                  BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (roa_id, prefix, prefixlen, max_prefixlen),
        CONSTRAINT              roa_prefix_roa_id
        FOREIGN KEY             (roa_id) REFERENCES roa (roa_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE ghostbuster (
        ghostbuster_id          SERIAL NOT NULL,
        vcard                   LONGBLOB NOT NULL,
        cert                    LONGBLOB NOT NULL,
        ghostbuster             LONGBLOB NOT NULL,
        published               DATETIME,
        self_id                 BIGINT UNSIGNED NOT NULL,
        ca_detail_id            BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (ghostbuster_id),
        CONSTRAINT              ghostbuster_self_id
        FOREIGN KEY             (self_id) REFERENCES self (self_id) ON DELETE CASCADE,
        CONSTRAINT              ghostbuster_ca_detail_id
        FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail (ca_detail_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE ee_cert (
        ee_cert_id              SERIAL NOT NULL,
        ski                     BINARY(20) NOT NULL,
        cert                    LONGBLOB NOT NULL,
        published               DATETIME,
        self_id                 BIGINT UNSIGNED NOT NULL,
        ca_detail_id            BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (ee_cert_id),
        CONSTRAINT              ee_cert_self_id
        FOREIGN KEY             (self_id) REFERENCES self (self_id) ON DELETE CASCADE,
        CONSTRAINT              ee_cert_ca_detail_id
        FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail (ca_detail_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Local Variables:
-- indent-tabs-mode: nil
-- End:
