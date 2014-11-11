Cryptography and Network Security 1: final project
Doug Norton, Brennan Cozzens, Richard Pietrzak, Jie Hu
======================================================

bank: stores account records; runs command shell that can deposit money and view balances; receives and sends messages to proxy

atm: users can login, use command shell to execute various commands; receives and sends messages to proxy; multiple can be connected to bank at once

proxy: relays messages between bank and ATM. will mostly be used for attack portion of project

executables in /bin are compiled from /src as follows:
g++ <file>.cpp -o ../bin/<file>.exe -l pthread -Wall