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


all: build/bin/tableau-parm


build/bin:
	mkdir -p build/bin

build/bin/tableau-parm: build/bin src/tableau-parm.c Makefile
	$(CC) $(OPTS) -o $@ src/tableau-parm.c


install: all
	install -D build/bin/tableau-parm $(BIN_PREFIX)/tableau-parm


clean:
	rm -rf build/*
