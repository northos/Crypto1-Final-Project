/**
	@file bank.cpp
	@brief Top level bank implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include "cryptopp/aes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/ccm.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/pssr.h"

#include <map>
#include <iostream>

 /*string is USERNAME, int is BALANCE. */
 /* The PINS are no longer stored in the bank, as only the atm needs theml. Now the key is just the username, much simpler*/
std::map<const std::string , int> accounts;
std::map<const std::string , pthread_mutex_t> mutexs;
int num_threads;

void* client_thread(void* arg);
void* console_thread(void* arg);

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}
	
	unsigned short ourport = atoi(argv[1]);
	
	//socket setup
	int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!lsock || lsock < 0)
	{
		printf("fail to create socket\n");
		return -1;
	}
	
	//listening address
	sockaddr_in addr_l;
	addr_l.sin_family = AF_INET;
	addr_l.sin_port = htons(ourport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr_l.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != bind(lsock, reinterpret_cast<sockaddr*>(&addr_l), sizeof(addr_l)))
	{
		printf("failed to bind socket\n");
		return -1;
	}
	if(0 != listen(lsock, SOMAXCONN))
	{
		printf("failed to listen on socket\n");
		return -1;
	}
	
	//Create initial bank accounts for Alice, Bob, and Eve
	accounts.insert ( std::pair<const std::string, int>("Alice",100) );
	accounts.insert ( std::pair<const std::string, int>("Bob",50) );
	accounts.insert ( std::pair<const std::string, int>("Eve",0) );
	mutexs.insert ( std::pair<const std::string, pthread_mutex_t>("Alice",PTHREAD_MUTEX_INITIALIZER) );
	mutexs.insert ( std::pair<const std::string, pthread_mutex_t>("Bob",PTHREAD_MUTEX_INITIALIZER) );
	mutexs.insert ( std::pair<const std::string, pthread_mutex_t>("Eve",PTHREAD_MUTEX_INITIALIZER) );
	
	pthread_t cthread;
	pthread_create(&cthread, NULL, console_thread, NULL);

	num_threads = 0;
	
	//loop forever accepting new connections
	while(1)
	{
		sockaddr_in unused;
		socklen_t size = sizeof(unused);
		int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
		if(csock < 0)	//bad client, skip it
			continue;
			
		// only create up to 5 active connections to prevent DDoS
		if(num_threads < 5)
		{
			num_threads++;
			pthread_t thread;
			pthread_create(&thread, NULL, client_thread, (void*)(&csock));
		}
		else
		{
		  printf("[bank] declined client ID #%d: too many connections\n", csock);
		}
	}
}

void* client_thread(void* arg)
{
	int csock = *(int*)arg;
	
	printf("[bank] client ID #%d connected\n", csock);
	
	//input loop
	unsigned int length;
	char packet[1024];
	const char *tok = " ";
	char *token;
	char *username;
	char *command;
	std::string user = "";
	int amount;
	std::map<const std::string , int>::iterator itr;
	std::map<const std::string , int>::iterator transfer_itr;
	std::string plaintext, ciphertext, signature, message_digest, atm_digest;
	char* transfer_username;
	bool session_active = false;
	bool key_generated = false;

	CryptoPP::AutoSeededRandomPool rng;
	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	byte iv[CryptoPP::AES::DEFAULT_KEYLENGTH];

	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aes_decrypt;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes_encrypt;

	CryptoPP::Integer bank_modulus( "0x0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000");
	CryptoPP::Integer bank_priv_key("0x0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
	      			   	   0000000000000000000000000000000000000000000000000000000000000000");
	CryptoPP::Integer bank_pub_key(	"0x00");


	CryptoPP::Integer atm_modulus(	"0x0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   0000000000000000000000000000000000000000000000000000000000000000\
					   000000000000000000000000000000000000000000000000000000000000");

	CryptoPP::Integer atm_pub_key(	"0x00");

	CryptoPP::RSA::PrivateKey privkey;
	CryptoPP::RSA::PublicKey bankpubkey;
	CryptoPP::RSA::PublicKey pubkey;
	privkey.Initialize(bank_modulus, bank_pub_key, bank_priv_key);
	bankpubkey.Initialize(bank_modulus, bank_pub_key);
	pubkey.Initialize(atm_modulus, atm_pub_key);
	CryptoPP::RSAES_OAEP_SHA_Encryptor rsa_encrypt (pubkey);
	CryptoPP::RSASS<CryptoPP::PSS,CryptoPP::SHA256>::Signer rsa_sha_sign (privkey);
	CryptoPP::SHA256 hash;
	byte mdigest[CryptoPP::SHA256::DIGESTSIZE];
	byte atm_hash[CryptoPP::SHA256::DIGESTSIZE];
	long int prevTimestamp;

	while(1)
	{
		//read the packet from the ATM
		if(sizeof(int) != recv(csock, &length, sizeof(int), 0))
			break;
		if(length >= 1024)
		{
			printf("packet too long\n");
			break;
		}

		if(length != recv(csock, packet, length, 0))
		{
			printf("[bank] fail to read packet\n");
			break;
		}

		// ATM hasn't tried to log in yet
		if (!key_generated)
		{
    			token = strtok(packet, tok);

			// Open a session
			if(!strncmp(token, "open", 4))
			{
				// Get current time
				token = strtok(NULL, tok);
				long int timestamp = atol(token);
				time_t now = time(0);
			
				// Discard old or oddly timed packets
				if (now < timestamp || now > timestamp + 5 || timestamp < prevTimestamp)
				{
					continue;
				}
				prevTimestamp = timestamp;

				// Generate session key and IV
				rng.GenerateBlock(key, sizeof(key));
				rng.GenerateBlock(iv, sizeof(iv));

				// Setup aes cipher for encryption and decryption
				aes_encrypt.SetKeyWithIV(key, sizeof(key), iv);
				aes_decrypt.SetKeyWithIV(key, sizeof(key), iv);

				// Copy key and IV into packet
				memcpy(packet, key, 16);
				memcpy(packet+16, iv, 16);
				memcpy(packet+32, "\0", 1);
				length = 32;

				// Attach timestamp
				now = time(0);
				char tmp[11];
				sprintf(tmp, "%ld", (long) now);
				strcat(packet, " ");
				strcat(packet, tmp);
				length += 1 + strlen(tmp);
				
				// Sign message with bank's private key
				plaintext.assign(packet, length);
				signature = "";
				CryptoPP::StringSource ss1(plaintext, true,
					new CryptoPP::SignerFilter(rng, rsa_sha_sign,
						new CryptoPP::StringSink(signature)
					)
				);

				plaintext.assign(packet, length);
				plaintext.append(signature);

				// Encrypt message with atm's public key
				ciphertext = "";
				CryptoPP::StringSource(plaintext, true,
					new CryptoPP::PK_EncryptorFilter(rng, rsa_encrypt,
						new CryptoPP::StringSink(ciphertext)
					)
				);
				
				memcpy (packet, ciphertext.c_str(), ciphertext.length());
				length = ciphertext.length();
				key_generated = true;
			}
			
		}
		else
		{
			ciphertext.assign(packet, length);

			// Decrypt packet
			plaintext = "";
			CryptoPP::StringSource( ciphertext, true,
				new CryptoPP::StreamTransformationFilter (aes_decrypt,
					new CryptoPP::StringSink( plaintext )
				)
			);

			atm_digest = plaintext.substr(plaintext.length() - CryptoPP::SHA256::DIGESTSIZE);
			plaintext.resize(plaintext.length() - CryptoPP::SHA256::DIGESTSIZE);

			// Calculate hash of message
			message_digest = "";
			CryptoPP::StringSource(plaintext, true,
				new CryptoPP::HashFilter(hash,
					new CryptoPP::StringSink(message_digest)
				)
			);

			// Compare calculated hash to hash sent by bank
			if (message_digest != atm_digest)
			{
				puts("Hash does not match.");
				puts("Killing session.");
				session_active = false;
				break;
			}
			else
			{
				strncpy(packet, plaintext.c_str(), 1023);
			}
			
			char *message[10];
			int num_args;
    			token = strtok(packet, tok);

			//Read all arguments
			for (num_args = 0; num_args < 10; ++num_args)
			{
				if (token == NULL) break;
				
				message[num_args] = token;
				token = strtok(NULL, tok);
			}
			
			username = message[0];
			command = message[1];

			long int timestamp = atol(message[num_args-1]);
			time_t now = time(0);

			// Get username from ATM
			if (!session_active)
			{
				session_active = true;
    				itr = accounts.find(username);
    				if(itr == accounts.end())
				{
    					strncpy(packet, "Invalid_Request", 1023);
					length = strlen("Invalid_Request");
    				}
				else
				{
					user = username;
					strncpy(packet, "You_are_logged_in", 1023);
					length = strlen(packet);
				}
			}
			else if (user != username)
			{
				strncpy(packet, "Invalid_Request", 1023);
			}
			else if (now < timestamp || now > timestamp+5 || timestamp < prevTimestamp)
			{
				strncpy(packet, "Denied_Bad_Timestamp", 1023);
				length = strlen(packet);
			}
			else 
			{
			        prevTimestamp = timestamp;
			  
				// Prevent multiple ATMs from changing account balance at the same time
				std::map<const std::string , pthread_mutex_t>::iterator mutex_itr = mutexs.find(username);
				pthread_mutex_lock(&(mutex_itr->second));

				// Show curent account balance
				if(!strncmp(command, "balance", 7))
				{
					char* holder;
					char balance[80];
					snprintf(balance, 80,"%d", accounts[username]);
					strncpy(packet, balance, 80);
					length = strlen(packet);
				}
				
				// Withdraw funds from account
				else if(!strncmp(command, "withdraw", 8) && num_args == 4)
				{
					amount = atoi(message[2]);
					if(amount > 0 && itr->second >=amount)
					{
						itr->second-=amount;
						strncpy(packet, "Confirmed", 1023);
						length = strlen("Confirmed");
					}
					else
					{
						strncpy(packet, "Denied", 1023);
						length = strlen("Denied");
					}
				}
				
				// Transfer funds to another account
				else if(!strncmp(command, "transfer", 8) && num_args == 5)
				{
					amount = atoi(message[2]);
					transfer_username = message[3];
					
					transfer_itr = accounts.find(transfer_username);
					if(transfer_itr != accounts.end() && transfer_itr != itr && amount > 0 && itr->second >=amount)
					{
						std::map<const std::string , pthread_mutex_t>::iterator transfer_mutex_itr = mutexs.find(transfer_username);
						pthread_mutex_lock(&(transfer_mutex_itr->second));
						itr->second-=amount;
						transfer_itr->second+=amount;
						strncpy(packet, "Confirmed", 1023);
						length = strlen("Confirmed");
						pthread_mutex_unlock(&(transfer_mutex_itr->second));
					}
					else
					{
						strncpy(packet, "Denied",1023);
						length = strlen("Denied");
					}
				}
				else if(!strncmp(command, "logout", 6))
				{
					session_active = false;
					user = "";
				}
				
				else{
					strncpy(packet, "Invalid_Request", 1023);
					length = strlen("Invalid_Request");
				}

			
				pthread_mutex_unlock(&(mutex_itr->second));
			}

			// Attach timestamp
			now = time(0);
			char tmp[11];
			sprintf(tmp, "%ld", (long) now);
			strcat(packet, " ");
			strcat(packet, tmp);
			length = strlen(packet);

			plaintext.assign(packet, length);

			// Hash message prior to sending
			message_digest = "";
			CryptoPP::StringSource(plaintext, true,
				new CryptoPP::HashFilter(hash,
					new CryptoPP::StringSink(message_digest)
				)
			);

			// Append hash to message
			plaintext += message_digest;

			// Encrypt packet
			ciphertext = "";
			CryptoPP::StringSource( plaintext, true,
				new CryptoPP::StreamTransformationFilter (aes_encrypt,
					new CryptoPP::StringSink( ciphertext )
				)
			);

			memcpy(packet, ciphertext.c_str(), ciphertext.length());
			length = ciphertext.length();
		}
		
		if(sizeof(int) != send(csock, (void *)&length, sizeof(int), 0))
		{
			printf("[bank] fail to send packet length\n");
			break;
		}
		if(length != send(csock, (void*)packet, length, 0))
		{
			printf("[bank] fail to send packet\n");
			break;
		}
		if(!strncmp(packet, "Invalid_Request", 15))
		{
			printf("client ID #%d sent invalid request.\n", csock);
			break;
		}
	}

	printf("[bank] client ID #%d disconnected\n", csock);
	num_threads--;
	close(csock);
	return NULL;
}

void* console_thread(void* arg)
{
	char buf[80];
	const char *tok = " ";
	char* token;
	char* username;
	while(1)
	{
		printf("bank> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
		

		// Blank Input
		if (!strncmp(buf, "", 79))
		{
			continue;
		}
		else
		{
			token = strtok(buf, tok);
			username = strtok(NULL, tok);
			if (username == NULL)
			{
				printf("Invalid Request");
				continue;
			}
			//get user
			std::map<const std::string , int>::iterator itr = accounts.find(username);

			if (itr == accounts.end())
			{
				printf("User: %s does not exist\n", username);
				continue;
			}
		}

		std::map<const std::string , int>::iterator itr = accounts.find(username);
		//deposit
		if(!strncmp(token, "deposit", 7))
		{
			char* amount_chr = strtok(NULL, tok);
			if (amount_chr == NULL)
			{
				printf("Invalid Request");
				continue;
			}
			int amount = atoi(amount_chr);

			std::map<const std::string , pthread_mutex_t>::iterator mutex_itr = mutexs.find(username);
    			pthread_mutex_lock(&(mutex_itr->second));

			if (itr == accounts.end())
			{
				puts("User does not exist");
			}
			if (amount < 0)
			{
				// Deposit is negative
				puts("Deposit must be a positive value");
			}
			else if (amount + itr->second < itr->second)
			{
				// Prevents overflow on account balance
				puts("Cannot deposit amount, maximum account balance will be exceeded");
			}
			else
			{
				//add balance
				itr->second += amount;
			}
			pthread_mutex_unlock(&(mutex_itr->second));
		}
		//balance
		else if(!strncmp(token, "balance", 7))
		{
			printf("Balance: %d\n", itr->second);
		}
		else
		{
			puts("Invalid Command");
		}
	}
}
