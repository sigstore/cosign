#!/bin/bash

set -feuo pipefail

ARGS="--tls \
    --cert /test/redis-tls/redis/cert.pem \
    --key /test/redis-tls/redis/key.pem \
    --cacert /test/redis-tls/minica.pem \
    --user replication-user \
    --pass 435e9c4225f08813ef3af7c725f0d30d263b9cd3"

if ! redis-cli \
    --cluster check \
      10.33.33.2:4218 \
    $ARGS ; then
  echo "Cluster needs creation!"
  redis-cli \
    --cluster-yes \
    --cluster create \
      10.33.33.2:4218 10.33.33.3:4218 10.33.33.4:4218 \
      10.33.33.5:4218 10.33.33.6:4218 10.33.33.7:4218 \
    --cluster-replicas 1 \
    $ARGS
fi

# Hack: run redis-server so we have something listening on a port.
# The Boulder container will wait for this port on this container to be
# available before starting up.
echo "Starting a server so everything knows we're done."
redis-server /test/redis.config
