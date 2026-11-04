#!/bin/sh
# SPDX-License-Identifier: MIT
# Ordinary-user install/run/remove test; refuses pre-existing package/files.
set -eu
umask 077
test "$#" -eq 6 && test "$(id -u)" -ne 0 || { echo 'usage: test_package.sh BUILD PACKAGE NEW_EVIDENCE UID GID COMPAT_FIXTURE (ordinary user)' >&2; exit 2; }
build=$1 package=$2 out=$3 uid=$4 gid=$5 compat=$6
test ! -e "$out"
for file in /usr/local/bin/procmon /usr/local/share/man/man1/procmon.1.gz /usr/local/share/doc/procmon-freebsd/README.md /usr/local/share/doc/procmon-freebsd/LICENSE /usr/local/share/doc/procmon-freebsd/SQLITE-NOTICE /usr/local/share/doc/procmon-freebsd/EASYLOGGINGPP-LICENSE; do
    test ! -e "$file" && test ! -L "$file" || { echo "refusing existing destination: $file" >&2; exit 1; }
done
if pkg info -e procmon-freebsd; then echo 'refusing pre-existing package' >&2; exit 1; fi
mkdir "$out"
chmod 0711 "$out"
installed=0
cleanup()
{
    if [ "$installed" -eq 1 ]; then doas pkg delete -y procmon-freebsd > "$out/failure-cleanup.log" 2>&1; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
pkg query -F "$package" '%n-%v' > "$out/package-identity.txt"
doas pkg add "$package" > "$out/install.log" 2>&1
installed=1
pkg info -l procmon-freebsd > "$out/installed-files.txt"
doas pkg check -s procmon-freebsd > "$out/integrity.log" 2>&1
/usr/local/bin/procmon --version > "$out/version.txt"
/usr/local/bin/procmon --help > "$out/help.txt"
ldd /usr/local/bin/procmon > "$out/libraries.txt"
doas "$build/test_freebsd_runtime" /usr/local/bin/procmon "$build/freebsd_app_fixture" "$compat" "$out" "$uid" "$gid" all > "$out/runtime.log" 2>&1
doas /usr/local/bin/procmon -f "$out/all.db" --dump > "$out/all.jsonl"
gzip -dc /usr/local/share/man/man1/procmon.1.gz | mandoc -T utf8 > "$out/manual.txt"
sha256 /usr/local/bin/procmon > "$out/installed-binary.sha256"
doas pkg delete -y procmon-freebsd > "$out/deinstall.log" 2>&1
installed=0
if pkg info -e procmon-freebsd; then exit 1; fi
for file in /usr/local/bin/procmon /usr/local/share/man/man1/procmon.1.gz /usr/local/share/doc/procmon-freebsd/README.md /usr/local/share/doc/procmon-freebsd/LICENSE /usr/local/share/doc/procmon-freebsd/SQLITE-NOTICE /usr/local/share/doc/procmon-freebsd/EASYLOGGINGPP-LICENSE; do
    test ! -e "$file" && test ! -L "$file"
done
echo 'PASS: guarded package install, integrity, installed full-catalog capture/replay/manual, and clean removal'
