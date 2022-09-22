CC = gcc
CFLAGS = -Wall
MAINFILE = gdoi_server.c
FFLAGS = -lssl -lcrypto -lpthread
OUTFILE = server.out
HFILESPATH = ../../gdoi_base/src
CFILES = $(HFILESPATH)/auxf.c $(HFILESPATH)/crypto.c $(HFILESPATH)/gdoi.c $(HFILESPATH)/client.c $(HFILESPATH)/isakmp.c

sec: $(MAINFILE) $(CFILES)
	$(CC) $(CFLAGS) -o $(OUTFILE) $(MAINFILE) $(CFILES) -I$(HFILESPATH) $(FFLAGS)