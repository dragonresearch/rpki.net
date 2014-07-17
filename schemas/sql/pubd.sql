-- $Id$

-- Copyright (C) 2012--2014  Dragon Research Labs ("DRL")
-- Portions copyright (C) 2009--2010  Internet Systems Consortium ("ISC")
-- Portions copyright (C) 2008  American Registry for Internet Numbers ("ARIN")
--
-- Permission to use, copy, modify, and distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notices and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
-- WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
-- WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
-- ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
-- CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
-- OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
-- NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
-- WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-- SQL objects needed by pubd.py.

-- Old tables that should just be flushed if present at all.

DROP TABLE IF EXISTS config;
DROP TABLE IF EXISTS snapshot;

-- DROP TABLE commands must be in correct (reverse dependency) order
-- to satisfy FOREIGN KEY constraints.

DROP TABLE IF EXISTS object;
DROP TABLE IF EXISTS delta;
DROP TABLE IF EXISTS session;
DROP TABLE IF EXISTS client;

CREATE TABLE client (
        client_id               SERIAL NOT NULL,
        client_handle           VARCHAR(255) NOT NULL,
        base_uri                TEXT,
        bpki_cert               LONGBLOB,
        bpki_glue               LONGBLOB,
        last_cms_timestamp      DATETIME,
        PRIMARY KEY             (client_id),
        UNIQUE                  (client_handle)
) ENGINE=InnoDB;

CREATE TABLE session (
        session_id              SERIAL NOT NULL,
        uuid                    VARCHAR(36) NOT NULL,
        serial                  BIGINT UNSIGNED NOT NULL,
        snapshot                TEXT,
        hash                    CHAR(64),
        PRIMARY KEY             (session_id),
        UNIQUE                  (uuid)
) ENGINE=InnoDB;

CREATE TABLE delta (
        delta_id                SERIAL NOT NULL,
        serial                  BIGINT UNSIGNED NOT NULL,
        xml                     TEXT NOT NULL,
        hash                    CHAR(64) NOT NULL,
        expires                 DATETIME NOT NULL,
        session_id              BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (delta_id),
        CONSTRAINT              delta_session_id
        FOREIGN KEY             (session_id) REFERENCES session (session_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE object (
        object_id               SERIAL NOT NULL,
        uri                     VARCHAR(255) NOT NULL,
        der                     LONGBLOB NOT NULL,
        hash                    CHAR(64) NOT NULL,
        client_id               BIGINT UNSIGNED NOT NULL,
        session_id              BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (object_id),
        CONSTRAINT              object_client_id
        FOREIGN KEY             (client_id) REFERENCES client (client_id) ON DELETE CASCADE,
        CONSTRAINT              object_session_id
        FOREIGN KEY             (session_id) REFERENCES session (session_id) ON DELETE CASCADE,
        UNIQUE                  (session_id, hash)
) ENGINE=InnoDB;

-- Local Variables:
-- indent-tabs-mode: nil
-- End:
