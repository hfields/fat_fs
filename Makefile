CC      =       gcc
SHELL   =       /bin/sh
CFLAGS  =       -g -Og $(PKGFLAGS)

PKGFLAGS        =       `pkg-config fuse --cflags --libs`