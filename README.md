# HOKUTO
# AI coded
# From scratch KISS like (https://kisslinux.github.io/wiki/package-manager) package manager in GO
# Supports standard KISS package structure
# Main configuration file /etc/hokuto.conf
# Most flags can be overriden by environment variables
HOKUTO_PATH=/repo/sauzeros/core:/repo/sauzeros/extra
TMPDIR=/var/tmp/hokuto
TMPDIR2=/var/tmpdir
HOKUTO_ROOT=/tmp/hokuto/
HOKUTO_LTO=1
CFLAGS=-march=native -mtune=native -O2 -pipe -fomit-frame-pointer
CXXFLAGS=-march=native -mtune=native -O2 -pipe -fomit-frame-pointer
LDFLAGS=-fuse-ld=mold -O1 -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
CFLAGS_LTO=-march=native -O2 -pipe -fomit-frame-pointer -flto=auto 
LDFLAGS_LTO=-fuse-ld=bfd -flto=auto -O1 -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# HOKUTO_DEBUG=1: enable build output to TTY and keep tmpdirs
# Live build log is in $TMPDIR/pkgname/log/build-log.txt

# Config per package (add empty file in package dir)
nostrip -> disable stripping
noram   -> build package in TMPDIR2, override TMPDIR is set to RAM 
asroot  -> build package as root



