#!/bin/sh -e

VERSION=$(cat VERSION)
MIRROR=$(cat internal/hokuto/assets/MIRROR)
TAG="v$VERSION"
BUILD_DATE=$(date +"%Y-%m-%d %H:%M:%S %Z")
ARCHES="amd64 arm64"

# The build artifacts are removed however the script ends.
cleanup() {
    for arch in $ARCHES; do
        rm -f "hokuto-$arch" "hokuto-$VERSION-$arch.tar.xz" "hokuto-$VERSION-$arch.tar.xz.sig"
    done
}
trap cleanup EXIT

# build_hokuto <goarch>: a static binary, packed and signed.
build_hokuto() {
    GOOS=linux GOARCH="$1" CGO_ENABLED=0 go build -trimpath -o "hokuto-$1" \
        -ldflags="-s -w -X 'hokuto/internal/hokuto.version=${VERSION}' \
        -X 'hokuto/internal/hokuto.buildDate=${BUILD_DATE}' \
        -X 'hokuto/internal/hokuto.defaultBinaryMirror=${MIRROR}'" \
        ./cmd/hokuto
    tar cvfJ "hokuto-$VERSION-$1.tar.xz" "hokuto-$1"
    # Signed by the host binary: hokuto-arm64 does not run here.
    ./hokuto-amd64 sign-file "hokuto-$VERSION-$1.tar.xz"
}

for arch in $ARCHES; do
    build_hokuto "$arch"
done

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

ASSETS="hokuto-$VERSION-amd64.tar.xz hokuto-$VERSION-arm64.tar.xz
hokuto-$VERSION-amd64.tar.xz.sig hokuto-$VERSION-arm64.tar.xz.sig
scripts/hokutostrap scripts/hokuto-builder"

# Check if release exists
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "Release $TAG exists, uploading assets"
    # shellcheck disable=SC2086
    gh release upload "$TAG" $ASSETS --clobber
else
    tmpfile=$(mktemp)
    ${EDITOR:-nano} "$tmpfile"
    # shellcheck disable=SC2086
    gh release create "$TAG" $ASSETS \
        --title "hokuto $TAG" \
        --notes-file "$tmpfile"
    rm "$tmpfile"
fi

# recipe_version prints the version of the hokuto recipe, found in
# HOKUTO_PATH (the environment's, else hokuto.conf's) as hokuto finds it.
recipe_version() {
    path=${HOKUTO_PATH:-$(sed -n 's/^HOKUTO_PATH=//p' /etc/hokuto/hokuto.conf 2>/dev/null | tail -n 1 | tr -d '"')}
    old_ifs=$IFS
    IFS=:
    for repo in $path; do
        if [ -f "$repo/hokuto/version" ]; then
            IFS=$old_ifs
            awk '{ print $1; exit }' "$repo/hokuto/version"
            return
        fi
    done
    IFS=$old_ifs
}

# changes_since <old version> lists the commits of this release, one
# "- subject" line each: those since the previous release's tag or, without
# that tag, since the last commit that set VERSION to an older version. The
# version commits themselves (subject "0.4.22") are left out.
changes_since() {
    since=""
    if git rev-parse -q --verify "refs/tags/v$1" >/dev/null; then
        since="v$1"
    else
        for commit in $(git log --format=%H -- VERSION); do
            if [ "$(git show "$commit:VERSION" 2>/dev/null)" != "$VERSION" ]; then
                since=$commit
                break
            fi
        done
    fi
    [ -n "$since" ] || return 0
    git log --no-merges --format='%s' "$since..$TAG" |
        grep -vE '^[0-9]+(\.[0-9]+)+$' |
        sed 's/^/- /'
}

# Package the release: a new VERSION becomes the recipe's version, a rebuild
# of the same one bumps its revision. Runs after the upload, since bump
# fetches the release tarball to update the checksums.
RECIPE_VERSION=$(recipe_version)
if [ -z "$RECIPE_VERSION" ]; then
    echo "No hokuto recipe found in HOKUTO_PATH; not bumping it."
elif [ "$RECIPE_VERSION" = "$VERSION" ]; then
    echo "Recipe already at $VERSION: bumping its revision"
    hokuto bump hokuto
else
    echo "Bumping the hokuto recipe from $RECIPE_VERSION to $VERSION"
    # The repository's prepare-commit-msg hook puts "hokuto: old → new" and
    # a blank line in front of the message, so it is just the changes.
    changes=$(changes_since "$RECIPE_VERSION")
    if [ -n "$changes" ]; then
        hokuto bump -m "$changes" hokuto "$VERSION"
    else
        hokuto bump hokuto "$VERSION"
    fi
fi
