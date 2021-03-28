FROM us-central1-docker.pkg.dev/dlorenc-vmtest2/test/golang:1.16.2 AS builder

ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./ $APP_ROOT/src/

RUN go build ./cmd/server

# Multi-Stage production build
FROM us-central1-docker.pkg.dev/dlorenc-vmtest2/test/distroless as deploy

# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/server /usr/local/bin/server

# Set the binary as the entrypoint of the container
CMD ["server", "serve"]
