# Boulder-Tools Docker Image Utilities

In CI and our development environment we do not rely on the Go environment of
the host machine, and instead use Go installed in a container. To simplify
things we separate all of Boulder's build dependencies into its own
`boulder-tools` Docker image.

## Setup

To build boulder-tools images, you'll need a Docker set up to do cross-platform
builds (we build for both amd64 and arm64 so developers with Apple silicon can use
boulder-tools in their dev environment). On Ubuntu the setup steps are:

```
docker buildx create --use --name=cross
sudo sudo apt-get install qemu binfmt-support qemu-user-static
```

After setup, the output of `docker buildx ls` should contain an entry like:

```
cross0  unix:///var/run/docker.sock running linux/amd64, linux/386, linux/arm64, linux/riscv64, linux/ppc64le, linux/s390x, linux/mips64le, linux/mips64, linux/arm/v7, linux/arm/v6
```

If you see an entry like:

```
cross0  unix:///var/run/docker.sock stopped
```

That's probably fine; the instance will be started when you run
tag_and_upload.sh (which runs `docker buildx build`).

## Go Versions

Rather than install multiple versions of Go within the same `boulder-tools`
container we maintain separate images for each Go version we support.

When a new Go version is available we perform several steps to integrate it
to our workflow:

1. We add it to the `GO_VERSIONS` array in `tag_and_upload.sh`.
2. We run the `tag_and_upload.sh` script to build, tag, and upload
   a `boulder-tools` image for each of the `GO_VERSIONS`
3. We update `.github/workflows/boulder-ci.yml`, adding the new docker image tag(s)
   to the `BOULDER_TOOLS_TAG` section.

After some time when we have spot checked the new Go release and coordinated
a staging/prod environment upgrade with the operations team we can remove the
old `GO_VERSIONS` entries, delete their respective build matrix items, and update
`docker-compose.yml`.
