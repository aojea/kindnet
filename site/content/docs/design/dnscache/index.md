---
title: "DNS cache"
date: 2025-01-17T22:54:48Z
---

## DNS cache

DNS is crucial in Kubernetes for service discovery, it uses  resolv.conf and search paths to enable service discovery. However, this setup can multiply DNS lookups, as the client need to iterate over the existing list of paths. In addition, if the application uses  "Happy Eyeballs" it will duplicate the number of queries, since it will query for A and AAAA records for each request.

The consequences is that the large number of queries per request increases latency and can exhaust the conntrack table, causing traffic disruption.

Kindnet implements a DNS cache to solve the DNS latency and uses a pool of TCP connections to pipeline the DNS request over a single connection to avoid the conntrack exhaustion.

In addition, it uses netfiler `nfqueue` functionality to avoid disrupting traffic, if is able to process the query, becuase it is cached or was able to obtain the answer via TCP, it replies spoofing the DNS server address and dropping the original request. If for any reason `kindnet` is not able to process the request, then it allowes the original request to go through. This is specially useful to minimize risks during rolling updates of kindet, to guarantee there will be no traffic disruption during this process.


<iframe src="https://docs.google.com/presentation/d/e/2PACX-1vQqB0gaV4b7Z0zrKDTvsE8hSZgAlMDEJ_cvVC4loNzk0cXKFuqLO4qZdvPUABVvkKQeC7LSergzVzmF/embed?start=false&loop=true&delayms=3000" frameborder="0" width="960" height="569" allowfullscreen="true" mozallowfullscreen="true" webkitallowfullscreen="true"></iframe>

You can find a demo during the SIG-Network meeting on Jan 16th 2024

https://www.youtube.com/playlist?list=PL69nYSiGNLP2E8vmnqo5MwPOY25sDWIxb
