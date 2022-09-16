# Redis

We use Redis Cluster for OCSP. The Boulder dev environment stands up a cluster
of 6 nodes, with 3 primaries and 3 replicas. Check docker-compose.yml for
details of those.

The initial setup is done by test/redis-create.sh, which assigns all the
individual Redis nodes to their roles as primaries or replicas.

## Debugging

Our main tool for interacting with our OCSP storage in Redis is cmd/rocsp-tool.
However, sometimes if things aren't working right you might want to drop down a
level.

The first tool you might turn to is `redis-cli`. You probably don't
have redis-cli on your host, so we'll run it in a Docker container. We
also need to pass some specific arguments for TLS and authentication. There's a
script that handles all that for you: `test/redis-cli.sh`. First, make sure your
redis cluster is running:

```
docker-compose up bredis_clusterer
```

Then, in a different window, run:

```
./test/redis-cli.sh -h 10.33.33.2
```

You can pass any IP address for the -h (host) parameter. The full list of IP
addresses for Redis nodes is in `docker-compose.yml`. You can also pass other
redis-cli commandline parameters. They'll get passed through.

You may want to go a level deeper and communicate with a Redis node using the
Redis protocol. Here's the command to do that (run from the Boulder root):

```
openssl s_client -connect 10.33.33.2:4218 \
  -CAfile test/redis-tls/minica.pem \
  -cert test/redis-tls/boulder/cert.pem \
  -key test/redis-tls/boulder/key.pem
```

Then, first thing when you connect, run `AUTH <user> <password>`. You can get a
list of usernames and passwords from test/redis.config.
