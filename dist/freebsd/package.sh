#!/bin/sh
# SPDX-License-Identifier: MIT
# Stage and create a local package. Never installs or changes system policy.
set -eu
umask 077
test "$#" -eq 2 || { echo 'usage: sh dist/freebsd/package.sh ABSOLUTE_BUILD NEW_ABSOLUTE_OUTPUT' >&2; exit 2; }
test "$(uname -s)" = FreeBSD
build=$1 out=$2
case "$build:$out" in /*:/*) ;; *) echo 'absolute paths required' >&2; exit 2;; esac
test -f "$build/CMakeCache.txt"
if grep -Eq '^PROCMON_USE_SYSTEM_(SQLITE|EASYLOGGINGPP):BOOL=ON$' "$build/CMakeCache.txt"; then
    echo 'system-library configurations must be packaged through the ports framework' >&2; exit 2
fi
if ! grep -q '^PROCMON_INSTALL_DOCS:BOOL=ON$' "$build/CMakeCache.txt"; then
    echo 'standalone packaging requires PROCMON_INSTALL_DOCS=ON' >&2; exit 2
fi
test ! -e "$out"
mkdir -p "$out/stage" "$out/manifest"
DESTDIR="$out/stage" cmake --install "$build" --prefix /usr/local --strip > "$out/install.log"
cat > "$out/manifest/+MANIFEST" <<MANIFEST
name: "procmon-freebsd"
version: "2.2.2.1"
origin: "sysutils/procmon-freebsd"
comment: "Community native FreeBSD syscall monitor"
desc: "Native FreeBSD 15.1 amd64 DTrace port of ProcMon-Linux, with terminal UI, private SQLite capture and typed replay."
maintainer: "ports@FreeBSD.org"
www: "https://github.com/microsoft/ProcMon-Linux"
prefix: "/usr/local"
abi: "$(pkg config ABI)"
licenselogic: "multi"
licenses: [ "MIT", "PD" ]
messages: [{ type: "install", message: "Live capture needs tracing privileges and the DTrace syscall provider. See man procmon and share/doc/procmon-freebsd/README.md. This is an unpublished community package, not an official Microsoft release." }]
MANIFEST
cat > "$out/plist" <<'PLIST'
bin/procmon
share/man/man1/procmon.1.gz
share/doc/procmon-freebsd/README.md
share/doc/procmon-freebsd/LICENSE
share/doc/procmon-freebsd/SQLITE-NOTICE
share/doc/procmon-freebsd/EASYLOGGINGPP-LICENSE
PLIST
pkg create -m "$out/manifest" -r "$out/stage" -p "$out/plist" -o "$out" > "$out/package.log"
sha256 "$out/"*.pkg > "$out/SHA256"
printf 'Created local package in %s\n' "$out"
