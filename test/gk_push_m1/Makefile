CC = gcc
CFLAGS = -Wall
MAINFILE = create_m1.c
FFLAGS = -lssl -lcrypto -lpthread
OUTFILE = test.out
HFILESPATH = ../../../gdoi_base/src
CFILES = $(HFILESPATH)/auxf.c $(HFILESPATH)/crypto.c $(HFILESPATH)/gdoi.c $(HFILESPATH)/client.c $(HFILESPATH)/isakmp.c

sec: $(MAINFILE) $(CFILES)
	$(CC) $(CFLAGS) -o $(OUTFILE) $(MAINFILE) $(CFILES) -I$(HFILESPATH) $(FFLAGS)