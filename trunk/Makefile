
CC=gcc
OPTS=-std=gnu89 -pedantic -Wall


all: build/bin/tableau-parm

build/bin:
	mkdir -p build/bin

build/bin/tableau-parm: build/bin src/tableau-parm.c
	$(CC) $(OPTS) -o $@ src/tableau-parm.c

clean:
	rm -rf build/*
