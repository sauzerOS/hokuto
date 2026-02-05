#!/bin/sh -e

VERSION=$(cat VERSION)
MIRROR=$(cat internal/hokuto/assets/MIRROR)
BUILD_DATE=$(date +"%Y-%m-%d %H:%M:%S %Z")

# build amd64
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0            # set 0 to avoid cgo and produce static bin when possible

go build -trimpath -o hokuto \
  -ldflags="-s -w -X 'hokuto/internal/hokuto.version=${VERSION}' \
  -X 'hokuto/internal/hokuto.buildDate=${BUILD_DATE}' \
  -X 'hokuto/internal/hokuto.defaultBinaryMirror=${MIRROR}'" \
  ./cmd/hokuto
