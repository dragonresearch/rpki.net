# RPKI Engine Common Configuration Options

Some of the configuration options are common to all of the daemons. Which
daemon they affect depends only on which sections of which configuration file
they are in.

The first group of options are boolean flags, which can be set to "true" or
"false". If not specified, default values will be chosen (generally false).
Many of these flags controll debugging code that is probably of interest only
to the developers.

debug_http::

> Enable verbose http debug logging.

want_persistent_client::

> Enable http 1.1 persistence, client side.

want_persistent_server::

> Enable http 1.1 persistence, server side.

use_adns::

> Use asynchronous DNS code. Enabling this will raise an exception if the
dnspython toolkit is not installed. Asynchronous DNS is an experimental
feature intended to allow higher throughput on busy servers; if you don't know
why you need it, you probably don't.

enable_ipv6_clients::

> Enable IPv6 HTTP client code.

enable_ipv6_servers::

> Enable IPv6 HTTP server code. On by default, since listening for IPv6
connections is usually harmless.

debug_cms_certs::

> Enable verbose logging about CMS certificates.

sql_debug::

> Enable verbose logging about sql operations.

gc_debug::

> Enable scary garbage collector debugging.

timer_debug::

> Enable verbose logging of timer system.

enable_tracebacks::

> Enable Python tracebacks in logs.

There are also a few options which allow you to save CMS messages for audit or
debugging. The save format is a simple MIME encoding in a
{{<http://en.wikipedia.org/wiki/Maildir|Maildir}-format> mailbox. The current
options are very crude, at some point we may provide finer grain controls.

dump_outbound_cms::

> Dump verbatim copies of CMS messages we send to this mailbox.

dump_inbound_cms::

> Dump verbatim copies of CMS messages we receive to this mailbox.

