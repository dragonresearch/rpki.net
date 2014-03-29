# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Upgrade RPKI SQL databases to schema expected by 0.5709.

NB: This code is evaluated in the context of rpki-sql-update and has
access to its global variables.
"""

rpkid_db.execute("""
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
    ) ENGINE=InnoDB
""")
