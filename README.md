ngx_http_sml
============

This is a nginx module for log

Directives
==========


sml_log
--------------------
**syntax:** *sml_log path [tail=on | off] level*

**default:** *sml_log logs/sax.log tail=off info*

**context:** *http, server, location*

this command record log dispatch from nginx log

when a request have debug_uri or debug_header or debug_body, then it can print this information log for online debug
