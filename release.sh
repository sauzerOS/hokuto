#!/bin/sh -e

VERSION=$(cat VERSION)
MIRROR=$(cat MIRROR)
TAG="v$VERSION"
BUILD_DATE=$(date +"%Y-%m-%d %H:%M:%S %Z")

# build amd64
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0            # set 0 to avoid cgo and produce static bin when possible
go build -trimpath -o hokuto-amd64 \
  -ldflags="-s -w -X 'hokuto/internal/hokuto.version=${VERSION}' \
  -X 'hokuto/internal/hokuto.buildDate=${BUILD_DATE}' \
-X 'hokuto/internal/hokuto.defaultBinaryMirror=${MIRROR}'" \
  ./cmd/hokuto
tar cvfJ hokuto-$VERSION-amd64.tar.xz hokuto-amd64

# build arm64
export GOOS=linux
export GOARCH=arm64
export CGO_ENABLED=0            # set 0 to avoid cgo and produce static bin when possible
go build -trimpath -o hokuto-arm64 \
  -ldflags="-s -w -X 'hokuto/internal/hokuto.version=${VERSION}' \
  -X 'hokuto/internal/hokuto.buildDate=${BUILD_DATE}' \
-X 'hokuto/internal/hokuto.defaultBinaryMirror=${MIRROR}'" \
  ./cmd/hokuto
tar cvfJ hokuto-$VERSION-arm64.tar.xz hokuto-arm64

# Check if tag exists locally
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Local tag $TAG already exists."
else
    echo "Creating local tag $TAG"
    git tag "$TAG"
fi

# Check if tag exists on remote
if git ls-remote --tags origin | grep -q "refs/tags/$TAG"; then
    echo "Remote tag $TAG already exists, not pushing."
else
    echo "Pushing tag $TAG to origin"
    git push origin "$TAG"
fi

# Check if release exists
if gh release view "v$VERSION" >/dev/null 2>&1; then
    echo "Release v$VERSION exists, uploading assets"
    gh release upload "v$VERSION" \
        hokuto-$VERSION-amd64.tar.xz \
        hokuto-$VERSION-arm64.tar.xz \
        --clobber
else
    tmpfile=$(mktemp)
    ${EDITOR:-nano} "$tmpfile"
    gh release create "v$VERSION" \
        hokuto-$VERSION-amd64.tar.xz \
        hokuto-$VERSION-arm64.tar.xz \
        --title "hokuto v$VERSION" \
        --notes-file "$tmpfile"
     rm "$tmpfile"
fi

# cleanup
rm -f hokuto-$VERSION-arm64.tar.xz hokuto-arm64
rm -f hokuto-$VERSION-amd64.tar.xz hokuto-amd64
