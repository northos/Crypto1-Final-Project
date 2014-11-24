CC=g++
OUTDIR=../bin/
CFLAGS=-lpthread 

all: bank atm proxy
	cp Alice.card $(OUTDIR)
	cp Bob.card $(OUTDIR)
	cp Eve.card $(OUTDIR)

bank: bank.cpp
	$(CC) $(CFLAGS) bank.cpp -o $(OUTDIR)bank -lcryptopp

atm: atm.cpp
	$(CC) $(CFLAGS) atm.cpp -o $(OUTDIR)atm -lcryptopp

proxy: proxy.cpp
	$(CC) $(CFLAGS) proxy.cpp -o $(OUTDIR)proxy -lcryptopp

clean:
	rm ../bin/*
