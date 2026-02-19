#!/bin/sh
set -e

if ! docker buildx version > /dev/null 2>&1; then
    printf 'Error: docker buildx is required\n' >&2
    exit 1
fi

rm -rf dist
mkdir -p dist

for plat in linux/amd64 linux/arm64; do
    suffix="${plat#linux/}"
    printf '=== Building xstrip for %s ===\n' "$plat"
    docker buildx build \
        --platform "$plat" \
        --target export \
        --build-arg "XSTRIP_VERSION=${XSTRIP_VERSION:-}" \
        --output "type=local,dest=dist/${suffix}" \
        .
    tar -czf "dist/xstrip-linux-${suffix}.tar.gz" \
        --mode='a+x' -C "dist/${suffix}" xstrip
    rm -rf "dist/${suffix}"
done

printf '\n=== dist/ contents ===\n'
ls -lh dist/
