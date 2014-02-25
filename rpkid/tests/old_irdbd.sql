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

-- SQL objects needed by irdbd.py.  You only need this if you're using
-- irdbd.py as your IRDB; if you have a "real" backend you can do
-- anything you like so long as you implement the relevant portion of
-- the left-right protocol.

-- DROP TABLE commands must be in correct (reverse dependency) order
-- to satisfy FOREIGN KEY constraints.

DROP TABLE IF EXISTS roa_request_prefix;
DROP TABLE IF EXISTS roa_request;
DROP TABLE IF EXISTS registrant_net;
DROP TABLE IF EXISTS registrant_asn;
DROP TABLE IF EXISTS registrant;
DROP TABLE IF EXISTS ghostbuster_request;
DROP TABLE IF EXISTS ee_certificate_asn;
DROP TABLE IF EXISTS ee_certificate_net;
DROP TABLE IF EXISTS ee_certificate;

CREATE TABLE registrant (
        registrant_id           SERIAL NOT NULL,
        registrant_handle       VARCHAR(255) NOT NULL,
        registrant_name         TEXT,
        registry_handle         VARCHAR(255),
        valid_until             DATETIME NOT NULL,
        PRIMARY KEY             (registrant_id),
        UNIQUE                  (registry_handle, registrant_handle)
) ENGINE=InnoDB;

CREATE TABLE registrant_asn (
        start_as                BIGINT UNSIGNED NOT NULL,
        end_as                  BIGINT UNSIGNED NOT NULL,
        registrant_id           BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (registrant_id, start_as, end_as),
        CONSTRAINT              registrant_asn_registrant_id
        FOREIGN KEY             (registrant_id) REFERENCES registrant (registrant_id)
                                ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE registrant_net (
        start_ip                VARCHAR(40) NOT NULL,
        end_ip                  VARCHAR(40) NOT NULL,
        version                 TINYINT UNSIGNED NOT NULL,
        registrant_id           BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (registrant_id, version, start_ip, end_ip),
        CONSTRAINT              registrant_net_registrant_id
        FOREIGN KEY             (registrant_id) REFERENCES registrant (registrant_id)
                                ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE roa_request (
        roa_request_id          SERIAL NOT NULL,
        self_handle             VARCHAR(255) NOT NULL,
        asn                     BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (roa_request_id)
) ENGINE=InnoDB;

CREATE TABLE roa_request_prefix (
        prefix                  VARCHAR(40) NOT NULL,
        prefixlen               TINYINT UNSIGNED NOT NULL,
        max_prefixlen           TINYINT UNSIGNED NOT NULL,
        version                 TINYINT UNSIGNED NOT NULL,
        roa_request_id          BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (roa_request_id, prefix, prefixlen, max_prefixlen),
        CONSTRAINT              roa_request_prefix_roa_request_id
        FOREIGN KEY             (roa_request_id) REFERENCES roa_request (roa_request_id)
                                ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE ghostbuster_request (
        ghostbuster_request_id  SERIAL NOT NULL,
        self_handle             VARCHAR(255) NOT NULL,
        parent_handle           VARCHAR(255),
        vcard                   LONGBLOB NOT NULL,
        PRIMARY KEY             (ghostbuster_request_id)
) ENGINE=InnoDB;

CREATE TABLE ee_certificate (
        ee_certificate_id       SERIAL NOT NULL,
        self_handle             VARCHAR(255) NOT NULL,
        pkcs10                  LONGBLOB NOT NULL,
        gski                    VARCHAR(27) NOT NULL,
        cn                      VARCHAR(64),
        sn                      VARCHAR(64),
        eku                     TEXT,
        valid_until             DATETIME NOT NULL,
        PRIMARY KEY             (ee_certificate_id),
        UNIQUE                  (self_handle, gski)
) ENGINE=InnoDB;

CREATE TABLE ee_certificate_asn (
        start_as                BIGINT UNSIGNED NOT NULL,
        end_as                  BIGINT UNSIGNED NOT NULL,
        ee_certificate_id       BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (ee_certificate_id, start_as, end_as),
        CONSTRAINT              ee_certificate_asn_ee_certificate_id
        FOREIGN KEY             (ee_certificate_id) REFERENCES ee_certificate (ee_certificate_id)
                                ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE ee_certificate_net (
        version                 TINYINT UNSIGNED NOT NULL,
        start_ip                VARCHAR(40) NOT NULL,
        end_ip                  VARCHAR(40) NOT NULL,
        ee_certificate_id       BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (ee_certificate_id, version, start_ip, end_ip),
        CONSTRAINT              ee_certificate_net_ee_certificate_id
        FOREIGN KEY             (ee_certificate_id) REFERENCES ee_certificate (ee_certificate_id)
                                ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- Local Variables:
-- indent-tabs-mode: nil
-- End:
