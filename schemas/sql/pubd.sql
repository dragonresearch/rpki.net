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

-- DROP TABLE commands must be in correct (reverse dependency) order
-- to satisfy FOREIGN KEY constraints.

DROP TABLE IF EXISTS object;
DROP TABLE IF EXISTS snapshot;
DROP TABLE IF EXISTS session;
DROP TABLE IF EXISTS client;

-- An old table that should just be flushed if present at all.

DROP TABLE IF EXISTS config;

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
        PRIMARY KEY             (session_id),
        UNIQUE                  (uuid)
) ENGINE=InnoDB;

CREATE TABLE snapshot (
        snapshot_id             SERIAL NOT NULL,
        activated               DATETIME,
        expires                 DATETIME,
        session_id              BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (snapshot_id),
        CONSTRAINT              snapshot_session_id
        FOREIGN KEY             (session_id) REFERENCES session (session_id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE object (
        object_id               SERIAL NOT NULL,
        uri                     VARCHAR(255) NOT NULL,
        hash                    CHAR(64) NOT NULL,
        payload                 LONGBLOB NOT NULL,
        published_snapshot_id   BIGINT UNSIGNED,
        withdrawn_snapshot_id   BIGINT UNSIGNED,
        client_id               BIGINT UNSIGNED NOT NULL,
        session_id              BIGINT UNSIGNED NOT NULL,
        PRIMARY KEY             (object_id),
        CONSTRAINT              object_published_snapshot_id
        FOREIGN KEY             (published_snapshot_id) REFERENCES snapshot (snapshot_id) ON DELETE SET NULL,
        CONSTRAINT              object_withdrawn_snapshot_id
        FOREIGN KEY             (withdrawn_snapshot_id) REFERENCES snapshot (snapshot_id) ON DELETE CASCADE,
        CONSTRAINT              object_client_id
        FOREIGN KEY             (client_id) REFERENCES client (client_id) ON DELETE CASCADE,
        CONSTRAINT              object_session_id
        FOREIGN KEY             (session_id) REFERENCES session (session_id) ON DELETE CASCADE,
        UNIQUE                  (session_id, hash)
) ENGINE=InnoDB;

-- Local Variables:
-- indent-tabs-mode: nil
-- End:
