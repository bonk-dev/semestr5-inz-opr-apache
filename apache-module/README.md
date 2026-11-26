# Moduł apache

Używany do trybu blokowania.

Szybkie uruchomienie serwera Apache z załadowanym modułem w celu testów. API musi nasłuchiwać na profilu HTTP (127.0.0.1:5292)

```sh
# uruchom API
dotnet run -lp http
```

demo:

```
[bonk@ARCH-BONK demo]$ ./run-apache.sh

Apache with mod_schiza on http://127.0.0.1:8080 (mode block, backend 127.0.0.1:5292)
[Thu Nov 26 15:20:41.932754 2026] [mpm_event:notice] [pid 86427:tid 86427] AH00489: Apache/2.4.71 (Unix) configured -- resuming normal operations
[Thu Nov 26 15:20:41.932811 2026] [core:notice] [pid 86427:tid 86427] AH00094: Command line: '/usr/bin/httpd -f /tmp/schiza-demo-sPXv7d/httpd.conf -D FOREGROUND'
[Thu Nov 26 15:20:43.282975 2026] [schiza:warn] [pid 86434:tid 86446] (110)Connection timed out: [client 127.0.0.1:45278] schiza: no answer from 127.0.0.1:5292, failing open
127.0.0.1 "GET / HTTP/1.1" 200 verdict=error score=- 100ms
127.0.0.1 "GET / HTTP/1.1" 304 verdict=allow score=0.00 73ms
127.0.0.1 "GET / HTTP/1.1" 200 verdict=allow score=0.00 4ms
127.0.0.1 "GET /favicon.ico HTTP/1.1" 404 verdict=allow score=0.00 1ms
[Thu Nov 26 15:21:01.062004 2026] [schiza:info] [pid 86434:tid 86451] [client 127.0.0.1:48656] schiza: blocked GET /.env HTTP/1.1 (score 1.00)
127.0.0.1 "GET /.env HTTP/1.1" 403 verdict=block score=1.00 2ms
^C[Thu Nov 26 15:21:06.573567 2026] [mpm_event:notice] [pid 86427:tid 86427] AH00491: caught SIGTERM, shutting down
[bonk@ARCH-BONK demo]$
```
