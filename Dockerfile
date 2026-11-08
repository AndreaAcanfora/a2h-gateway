# Build a static binary (pure-Go SQLite, no cgo), then ship it on a minimal image.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/a2h ./cmd/a2h

# distroless/static has CA certificates, runs as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
# Proves to the MCP Registry that this image belongs to the server it lists.
LABEL io.modelcontextprotocol.server.name="io.github.AndreaAcanfora/a2h-gateway"
COPY --from=build /out/a2h /usr/local/bin/a2h
WORKDIR /data
EXPOSE 8080
ENV A2H_DATA_DIR=/data
ENTRYPOINT ["a2h"]
CMD ["serve"]
