#!/usr/bin/env bash
set -euo pipefail

target="${1:?target is required}"
root="$(pwd -P)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
if command -v cygpath >/dev/null 2>&1; then
  root="$(cygpath -m "$root")"
  cargo_home="$(cygpath -m "$cargo_home")"
fi
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$root=/src"$'\x1f'"--remap-path-prefix=$cargo_home=/cargo"
export CARGO_INCREMENTAL=0
export SOURCE_DATE_EPOCH="$(git -c safe.directory="$root" show -s --format=%ct HEAD)"
export MACOSX_DEPLOYMENT_TARGET=11.0
export TZ=UTC LC_ALL=C
unset RUSTFLAGS

rustup target add "$target"
cargo build --release --locked --target "$target" -p mylonite

ext=""
[[ "$target" == *windows* ]] && ext=".exe"
mkdir -p dist
cp "target/$target/release/mylonite$ext" "dist/mylonite-$target$ext"
