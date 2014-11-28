Cryptography and Network Security 1: final project
Doug Norton, Brennan Cozzens, Richard Pietrzak, Jie Hu
======================================================

bank: stores account records; runs command shell that can deposit money and view balances; 
      receives and sends messages to proxy

atm: users can login, use command shell to execute various commands; receives and sends messages to proxy; 
     multiple can be connected to bank at once

proxy: relays messages between bank and ATM. will mostly be used for attack portion of project

executables are compiled via the makefile in /src

encryption uses the crypto++ library


Cryptosystem description:
- Communication: the ATMs and bank communicate primarily via the proxy server, which relays
  messages sent to it (to an ATM if sent by the bank, and vice versa). Messages are padded
  to a length of 1024 characters, hashed with SHA1, and encrypted with AES.

- Flow: Both the ATMs and the bank run a local console thread. The bank's console can be used
  to deposit money into an account or check its balance. Because a user's account cannot be
  negatively affected by this, there is no security aside from error checking (i.e. the user
  need not login). The ATM thread requires users to login with their name and PIN. PINs are retrieved
  from .card files: for example, Alice's login info is stored in the Alice.card
  file. Once logged in, the user can check their balance, withdraw funds, transfer funds,
  or log out. The first three of these require the ATM to get confirmation from the bank.
  It sends an encrypted, authorized, timestamped message to the bank with the appropriate command.
  If valid, the bank executes the operation and replies (again with an encrypted, authorized, timestamped
  message).

- Account storage: Accounts are stored in the Bank as a Map from username strings to integer
  balances. The bank also holds a mutex for each account so that the separate threads for
  different client connections don't conflict if there are multiple ATMs connected.

- Key sharing: The ATM and Bank communicate via AES-encrypted messages, thus they must share a session key.
  This is done upon opening a connection via RSA public-key encryption.

- Timeout: Messages with time stamps more than 5 seconds out of date will be rejected.
  Messages must also be received in order: messages with a timestamp older (or the same as) one previously
  received will be assumed to be a duplicate and rejected.