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
  messages sent to it (to an ATM if sent by the bank, and vice versa).  A description of the cryptographic
  protocol follows.
    1. The user inserts his card into the ATM and enters his pin.
    2. The ATM sends a command "open" in plaintext to open a session with the bank
    3. The bank randomly generates a session key and initialization vector
    4. The bank signs the session key by hashing the key, iv pair with SHA256 and encrypts it with its private key (RSA)
    5. The bank creates a packet with the following composition:  (Key || IV || H[Key || IV] || Ekpriv{H[Key || IV]})
    6. The ATM verifies that the message was generated by the bank using the signatur
    7. Once the authentication has been done, the ATM encrypts the username with the session key (AES-128 in CBC mode)
    8. All packets are time stamped to prevent replay attacks.  Any packet is considered expired after 5 seconds.
    9. Furthermore all packets are appended with a SHA256 digest of the message to prevent tampering.

- Flow: Both the ATMs and the bank run a local console thread. The bank's console can be used
  to deposit money into an account or check its balance. We assume that only trusted parties will have access
  to the bank console, so there is no security aside from error checking (i.e. the user
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

- Timeout: The bank will not accept messages whose timestamps are more than 5 seconds old, and won't 
  accept client connections more than 20 seconds old. The ATM will accept timestamps up to 20 seconds old.
  Messages must also be received in order: messages with a timestamp older (or the same as) one previously
  received will be assumed to be a duplicate and rejected.

  Pin numbers: The pin numbers were not hashed, since this information is necessary for testing.  The pin numbers
  for each user are provided below for convenience.
    *Alice	12306
    *Bob	340
    *Eve	276
