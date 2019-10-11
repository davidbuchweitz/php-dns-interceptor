# PHP DNS Interceptor

Intercepts DNS queries to answer from local database allowing wildcard
lookups. By default, a file named records will be loaded in the same
directory where script is executed from.

Records file format is one record per line:
<ip address> <domain>

```bash
127.0.0.1   mydomain.local
196.2.16.3  *.domain.local
172.16.0.6  *something*.*.org
```

Requires PHP5.6+ with sockets extension
