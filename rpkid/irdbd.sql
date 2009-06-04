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

-- SQL objects needed by irdbd.py.  You only need this if you're using
-- irdbd.py as your IRDB; if you have a "real" backend you can do
-- anything you like so long as you implement the relevant portion of
-- the left-right protocol.

DROP TABLE IF EXISTS registrant;

CREATE TABLE registrant (
        registrant_id           SERIAL NOT NULL,
        registrant_handle       VARCHAR(255) NOT NULL,
        registrant_name         TEXT,
        rpki_self_handle        VARCHAR(255),
        valid_until             DATETIME NOT NULL,
        PRIMARY KEY             (registrant_id),
        UNIQUE                  (rpki_self_handle, registrant_handle)
);

DROP TABLE IF EXISTS asn;

CREATE TABLE asn (
        asn_id          SERIAL NOT NULL,
        start_as        BIGINT unsigned NOT NULL,
        end_as          BIGINT unsigned NOT NULL,
        registrant_id   BIGINT unsigned NOT NULL,
        PRIMARY KEY     (asn_id),
        FOREIGN KEY     (registrant_id) REFERENCES registrant ON DELETE SET NULL ON UPDATE SET NULL
);

DROP TABLE IF EXISTS net;

CREATE TABLE net (
        net_id          SERIAL NOT NULL,
        start_ip        VARCHAR(40) NOT NULL,
        end_ip          VARCHAR(40) NOT NULL,
        version         TINYINT unsigned NOT NULL,
        registrant_id   BIGINT unsigned NOT NULL,
        PRIMARY KEY     (net_id),
        FOREIGN KEY     (registrant_id) REFERENCES registrant ON DELETE SET NULL ON UPDATE SET NULL
);

-- Local Variables:
-- indent-tabs-mode: nil
-- End:
