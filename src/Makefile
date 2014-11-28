CC=g++
OUTDIR=../bin/
CFLAGS=-lpthread -lcryptopp -static 

all: bank atm proxy
	cp Alice.card $(OUTDIR)
	cp Bob.card $(OUTDIR)
	cp Eve.card $(OUTDIR)

bank: bank.cpp
	$(CC) bank.cpp -o $(OUTDIR)bank $(CFLAGS) 

atm: atm.cpp
	$(CC) atm.cpp -o $(OUTDIR)atm $(CFLAGS)

proxy: proxy.cpp
	$(CC) proxy.cpp -o $(OUTDIR)proxy $(CFLAGS)

clean:
	rm ../bin/*
