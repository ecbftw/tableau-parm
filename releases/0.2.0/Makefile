# Makefile for tableau-parm
#
# $Id$

# Installation prefixes.  Change to install elsewhere.

PREFIX=/usr/local
BIN_PREFIX=$(PREFIX)/bin
DOC_PREFIX=$(PREFIX)/share/doc/tableau-parm
MAN_PREFIX=$(PREFIX)/man

################################################################################


CC=gcc
OPTS=-std=gnu89 -pedantic -Wall


all: build/bin/tableau-parm build/doc/man/man1/tableau-parm.1.gz


build/bin:
	mkdir -p build/bin

build/bin/tableau-parm: build/bin src/tableau-parm.c Makefile
	$(CC) $(OPTS) -o $@ -I/usr/local/include -L/usr/local/lib -lsgutils src/tableau-parm.c

build/doc/man/man1/tableau-parm.1.gz: doc/man/man1/tableau-parm.1.gz
	mkdir -p build/doc/man/man1
	cp doc/man/man1/tableau-parm.1.gz $@

install: all
	mkdir -p $(BIN_PREFIX)
	install build/bin/tableau-parm $(BIN_PREFIX)/tableau-parm
	mkdir -p $(DOC_PREFIX)
	cp -r build/doc/man $(DOC_PREFIX)
	ln -sf $(DOC_PREFIX)/man/man1/* $(MAN_PREFIX)/man1


clean:
	rm -rf build/*
