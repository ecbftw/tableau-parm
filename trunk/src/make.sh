#!/bin/sh

#gcc -c -o query-device.o query-device.c
#gcc -o query-device query-device.o /usr/lib/libraw1394.a


gcc -o query-scsi query-scsi.c

