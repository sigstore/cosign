#!/bin/bash
set -ex

echo "copying rekor repo"
cd $HOME
git clone https://github.com/sigstore/rekor.git
cd rekor

echo "starting services"
docker-compose up -d

count=0

echo -n "waiting up to 60 sec for system to start"
until [ $(docker-compose ps | grep -c "(healthy)") == 3 ];
do
    if [ $count -eq 6 ]; then
       echo "! timeout reached"
       exit 1
    else
       echo -n "."
       sleep 10
       let 'count+=1'
    fi
done

echo
echo "running tests"

cd $GITHUB_WORKSPACE
go build -o cosign ./cmd/cosign
go test -tags=e2e -race ./...


echo "cleanup"
cd $HOME/rekor
docker-compose down
