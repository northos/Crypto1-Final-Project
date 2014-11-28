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
	
	//loop forever accepting new connections
	while(1)
	{
		sockaddr_in unused;
		socklen_t size = sizeof(unused);
		int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
		if(csock < 0)	//bad client, skip it
			continue;
			
		pthread_t thread;
		pthread_create(&thread, NULL, client_thread, (void*)(&csock));
	}
}

void* client_thread(void* arg)
{
	int csock = *(int*)arg;
	
	printf("[bank] client ID #%d connected\n", csock);
	
	//input loop
	int length;
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

	CryptoPP::Integer bank_modulus( "0xbbed02f6dbb34c5aa313b9d6e54b3e862e0bd1d8d0d9b608cff72b5439ba40b0\
					   4c1aab93a17e176cd56ba2626f25f25160f51940c9299347f1adffb22192e20a\
					   e3b5205a2565b654a123914ada58946be5a16c9e070f90e25996efd8350b76eb\
					   197decf7aebe8c591ad2f3999ae125f8ad35b2b258b7e4134bf19aa803a8edf0\
					   533921256607dad00e6ddc3e1b78f4df3ff7918590a59a6cb2aded1a708cffca\
					   906abbea826f4973dc9d37e74d4e01d1b95f1e7abc425127178a3eb22dc03940\
					   4ed2bcd574954465c94af3a49ec6237ef8991c51b20ff8a818dba5149afae651\
					   11211f1a806526e62b3cbb852683f9d04981fddc5d10ed652cbc104cdf8b1be5");
	CryptoPP::Integer bank_priv_key("0x52e8905dd965b0be933d68938346d7d1c90536eeb67e2aa988ed0b961977d13e\
					   b829e248a9210a55a973401c5e366360233ef48d85ecb1eb08bdb4925a1b277d\
					   46577027c534670738082982e7dbc9026cd64681f40e659109683ca32675ffc2\
					   12c69d4018631fccf53ef300009081b17997b0b81814e49f19f9a61cf28e4ada\
					   35d45505429661e7dbc6225c0abb94c2e12372f5da871c4bfd54b525b04d27b5\
					   1605cb592faf9352daee996e0f482934d9796768bb4c3f4be4ceaccfce915fec\
					   28eb43f8dd09ca3876f11131705aa64342c5a2bfc8fea997ea82c6591f9ba5a3\
	      			   ce89b42ae6cf052d42b7451eafda6f22f696734ac716ba33e2c4b6514d0d295b");
	CryptoPP::Integer bank_pub_key(	"0x11");


	CryptoPP::Integer atm_modulus(	"0xe6950462319d89109fa52aed651b1739f657aa89d84182ffafcd8fc7f6b533a3\
					   edacb06a14c2d9f8a957d19f60b4ccc76297be744bc200e1f0aa3348095b317c\
					   42400f0d767b414b5deba8fb657fd3c6271e7f048640a267046995a8af66434d\
					   7a4efb511f92dff176099fc8bb7c4469892efd767d2d03f22872a213437bbcee\
					   14da0fd39b2d6d9e75eafbc559e0ffda8caed625371add100dab7035a3dc5e52\
					   4d0e8a04451ee61b6135e686c7c6842f524a3da2d6262387c43c30542f66105d\
					   8c017ae71ba2e56566e9cdbe8fdb8176768859362a59b79128027f1369c3f001\
					   8e7f102ee4202e07fdd5ddd5a6741fce8a8be2df4dc83fb2f5e85efa9ddecbea\
					   a00e0a816e741789c2fcfca35dabd25444ce300dd05661e9ba28934fc15039c8\
					   5aa6fb4ec353227b110da6ca15c1d75644a92b416310412a43ac6d04812abab5\
					   4c08f234d61106a32aed53c8e739ff97e65473f0c0d043364d24dd9caebf");

	CryptoPP::Integer atm_pub_key(	"0x11");

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

		if (!key_generated)
		{
    			token = strtok(packet, tok);

			if(!strcmp(token, "open"))
			{
				token = strtok(NULL, tok);
				long int timestamp = atol(token);
				time_t now = time(0);
			
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
				
				printf("%d\n", now);
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
				strncpy(packet, plaintext.c_str(), 1024);
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
			num_args;
			
			username = message[0];
			command = message[1];
			long int timestamp = atol(message[num_args-1]);
			time_t now = time(0);

			if (!session_active)
			{
				session_active = true;
    				itr = accounts.find(username);
    				if(itr == accounts.end())
				{
    					strcpy(packet, "Invalid_Request");
					length = strlen("Invalid_Request");
    				}
				else
				{
					user = username;
					strcpy(packet, "You_are_logged_in");
					length = strlen(packet);
				}
			}
			else if (user != username)
			{
				strncpy(packet, "Invalid_Request", 1024);
			}
			else if (now < timestamp || now > timestamp+5 || timestamp < prevTimestamp)
			{
				strcpy(packet, "Denied_Bad_Timestamp");
				length = strlen(packet);
			}
			else 
			{
			        prevTimestamp = timestamp;
			  
				std::map<const std::string , pthread_mutex_t>::iterator mutex_itr = mutexs.find(username);
				pthread_mutex_lock(&(mutex_itr->second));

				if(!strcmp(command, "balance"))
				{
					char* holder;
					char balance[80];
					snprintf(balance, 80,"%d", accounts[username]);
					strncpy(packet, balance, 80);
					length = strlen(packet);
				}
				
				else if(!strcmp(command, "withdraw") && num_args == 4){
					amount = atoi(message[2]);
					if(amount > 0 && itr->second >=amount){
						itr->second-=amount;
						strcpy(packet, "Confirmed");
						length = strlen("Confirmed");
					}
					else{
						strcpy(packet, "Denied");
						length = strlen("Denied");
					}
				}
				
				else if(!strcmp(command, "transfer") && num_args == 5){
					amount = atoi(message[2]);
					transfer_username = message[3];
					
					transfer_itr = accounts.find(transfer_username);
					if(transfer_itr != accounts.end() && transfer_itr != itr && amount > 0 && itr->second >=amount){
						std::map<const std::string , pthread_mutex_t>::iterator transfer_mutex_itr = mutexs.find(transfer_username);
						pthread_mutex_lock(&(transfer_mutex_itr->second));
						itr->second-=amount;
						transfer_itr->second+=amount;
						strcpy(packet, "Confirmed");
						length = strlen("Confirmed");
						pthread_mutex_unlock(&(transfer_mutex_itr->second));
					}
					else{
						strcpy(packet, "Denied");
						length = strlen("Denied");
					}
				}
				else if(!strcmp(command, "logout")){
					session_active = false;
					user = "";
				}
				
				else{
					strcpy(packet, "Invalid_Request");
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

			//puts(packet);
			plaintext.assign(packet, length);

			message_digest = "";
			CryptoPP::StringSource(plaintext, true,
				new CryptoPP::HashFilter(hash,
					new CryptoPP::StringSink(message_digest)
				)
			);

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
		if(!strncmp(packet, "Invalid_Request", 15)){
			printf("client ID #%d sent invalid request.\n", csock);
			break;
		}
	}

	printf("[bank] client ID #%d disconnected\n", csock);

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
		if (!strcmp(buf, ""))
		{
			continue;
		}
		else
		{
			token = strtok(buf, tok);
			username = strtok(NULL, tok);
		}

		//deposit
		if(!strcmp(token, "deposit")){
			int amount = atoi(strtok(NULL, tok));
			//get user
			std::map<const std::string , int>::iterator itr = accounts.find(username);

			if (itr == accounts.end())
			{
				printf("User: %s does not exist\n", username);
				continue;
			}

			std::map<const std::string , pthread_mutex_t>::iterator mutex_itr = mutexs.find(username);
    			pthread_mutex_lock(&(mutex_itr->second));

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
		else if(!strcmp(token, "balance")){
			std::map<const std::string , int>::iterator itr = accounts.find(username);
			if (itr == accounts.end()) {
				printf("User: %s does not exist\n", username);
				continue;
			}
			printf("Balance: %d\n", itr->second);
		}
		else
		{
			puts("Invalid Command");
		}
	}
}
