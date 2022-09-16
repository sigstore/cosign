#!/usr/bin/env bash
#
# Outer wrapper for invoking test.sh inside docker-compose.
#
if type realpath >/dev/null 2>&1 ; then
  cd "$(realpath -- $(dirname -- "$0"))"
fi
exec docker-compose run boulder ./test.sh "$@"
