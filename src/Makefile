CC=g++
OUTDIR=../bin/
CFLAGS=-lpthread -lcryptopp 

all: bank atm proxy
	cp Alice.card $(OUTDIR)
	cp Bob.card $(OUTDIR)
	cp Eve.card $(OUTDIR)

bank: bank.cpp
	$(CC) $(CFLAGS) bank.cpp -o $(OUTDIR)bank

atm: atm.cpp
	$(CC) $(CFLAGS) atm.cpp -o $(OUTDIR)atm

proxy: proxy.cpp
	$(CC) $(CFLAGS) proxy.cpp -o $(OUTDIR)proxy

clean:
	rm ../bin/*
