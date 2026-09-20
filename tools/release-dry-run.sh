#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-}"
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "release version must be an exact vX.Y.Z tag: $version" >&2
  exit 2
fi

if ! git -C "$root" diff --quiet || ! git -C "$root" diff --cached --quiet; then
  echo "release dry-run requires a clean worktree" >&2
  exit 2
fi

output="$root/dist/$version"
if [[ -e "$output" ]]; then
  echo "release output already exists: $output" >&2
  exit 2
fi

mkdir -p "$root/dist"
temporary="$(mktemp -d "$root/dist/.release-${version#v}-XXXXXX")"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

make -C "$root" check

native="$temporary/bebop"
go -C "$root" build -trimpath -ldflags "-X github.com/bebop-home/bebop/internal/buildinfo.Version=$version" -o "$native" ./cmd/bebop
if [[ "$("$native" version)" != "bebop $version" ]]; then
  echo "release binary version does not match requested tag" >&2
  exit 1
fi

targets=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
  windows/arm64
)
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
for target in "${targets[@]}"; do
  os="${target%%/*}"
  arch="${target##*/}"
  stage="$temporary/stage-$os-$arch"
  mkdir -p "$stage"
  binary="bebop"
  extension="tar.gz"
  if [[ "$os" == windows ]]; then
    binary="bebop.exe"
    extension="zip"
  fi
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go -C "$root" build -trimpath -ldflags "-X github.com/bebop-home/bebop/internal/buildinfo.Version=$version" -o "$stage/$binary" ./cmd/bebop
  cp "$root/README.md" "$stage/README.md"
  archive="$temporary/bebop_${version#v}_${os}_${arch}.$extension"
  if [[ "$extension" == zip ]]; then
    (cd "$stage" && zip -X -q "$archive" "$binary" README.md)
  else
    tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$stage" -czf "$archive" "$binary" README.md
  fi
done

(
  cd "$temporary"
  find . -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -printf '%f\n' | LC_ALL=C sort | xargs -r sha256sum > SHA256SUMS
)
mv "$temporary" "$output"
trap - EXIT
printf 'release dry-run artifacts: %s\n' "$output"
