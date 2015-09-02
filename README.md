ngx_http_sml
============

This is a nginx module for log base on ngx_lua_module

Directives
==========


sml_log
--------------------
**syntax:** *sml_log path [tail=on | off] level*

**default:** *sml_log logs/biz.log tail=off info*

**context:** *http, server, location*

this command record log dispatch from nginx log

**NOTE:** when a request have debug_uri or debug_header or debug_body, then it can print this information log for online debug

**example:** 

curl localhost:/xxx?debug_uri=true&debug_header=*&debug_body=true

then in lua land
```
local sml = require "sml"
sml.log(sml.info, ...)
```
the log will add request uri and all headers and body if have one in the log tail

we also can set debug_header to any header such as `host` etc... 
