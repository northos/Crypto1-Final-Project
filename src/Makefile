CC=g++
OUTDIR=../bin/
CFLAGS=-lpthread

all: bank atm proxy
	cp user.card $(OUTDIR)

bank: bank.cpp
	$(CC) bank.cpp -o $(OUTDIR)bank $(CFLAGS)

atm: atm.cpp
	$(CC) atm.cpp -o $(OUTDIR)atm $(CFLAGS)

proxy: proxy.cpp
	$(CC) proxy.cpp -o $(OUTDIR)proxy $(CFLAGS)

clean:
	rm ../bin/*
