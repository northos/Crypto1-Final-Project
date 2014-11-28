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
	char* token;
	char* username;
	std::string user = "";
	int amount;
	std::map<const std::string , int>::iterator itr;
	std::map<const std::string , int>::iterator transfer_itr;
	std::string plaintext, ciphertext;
	char* transfer_username;
	char session_active = 0;

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

	CryptoPP::Integer atm_modulus(	"0xe702c9e39c8deea1f2496b5535acc7839819c7e3b1124d360b4b33141db5632a\
					   f648c5da27708bd7f5f5f8d8f32e15960c4791d43ec92906a528157398695379\
					   037a9bfd0c580c276d37257a5c264a633f3fe4e16299177a1c4e54c2afa52103\
					   04f948853a986c14e6124ac7849c61a17f67666017d3f2e84666c329fff1a85b\
					   439c7f42dfbdc51e7b020fce5412eb087e1afc3c36c14523a4c714d169eec7f6\
					   6d42d97688aafbe12151de9fca9e26c91b7c424d02afe2533bfb26b88f850171\
					   c2629dd4f8268dc7daf7643d59997228c2cf25232f20f0b0d0536b6e92322cd1\
					   68d66d6708efa17a3747e6c72f1ecd84bfdc4e7979bf2653c4af23a792d2f86b");
	CryptoPP::Integer atm_pub_key(	"0x11");

	CryptoPP::RSA::PrivateKey privkey;
	CryptoPP::RSA::PublicKey pubkey;
	privkey.Initialize(bank_modulus, bank_pub_key, bank_priv_key);
	pubkey.Initialize(atm_modulus, atm_pub_key);
	CryptoPP::RSAES_OAEP_SHA_Encryptor rsa_encrypt (pubkey);
	CryptoPP::RSAES_OAEP_SHA_Decryptor rsa_decrypt (privkey);

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


		if (!session_active)
		{
			puts(packet);

    			token = strtok(packet, tok);

			if(!strcmp(token, "open"))
			{
				// Generate session key and IV
				rng.GenerateBlock(key, sizeof(key));
				rng.GenerateBlock(iv, sizeof(iv));

				// Setup aes cipher for encryption and decryption
				aes_encrypt.SetKeyWithIV(key, sizeof(key), iv);
				aes_decrypt.SetKeyWithIV(key, sizeof(key), iv);

				// Verify username exists
    				token = strtok(NULL, tok);
				
				if (token == NULL)
				{
					continue;
				}
				username = token;
				user = token;

    				itr = accounts.find(username);
    				if(itr == accounts.end()){
    					strcpy(packet, "Invalid Request");
					length = strlen("Invalid Request") + 1;
					packet[length - 1] = '\0';
    				}
				
				// DEBUG
				//puts("KEY:");
				//for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++)
				//{
				//	printf("%02x ", key[i]);
				//}
				//puts("");
				//puts("IV:");
				//for (int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++)
				//{
				//	printf("%02x ", iv[i]);
				//}
				//puts("");

				memcpy(packet, key, 16);
				memcpy(packet+16, iv, 16);
				memcpy(packet+32, "\0", 1);
				length = 32;
				
				plaintext.assign(packet, length);

				CryptoPP::StringSource(plaintext, true,
					new CryptoPP::PK_EncryptorFilter(rng, rsa_encrypt,
						new CryptoPP::StringSink(ciphertext)
					)
				);
				
				// DEBUG
				//puts("Encrypted");
				//for (int i = 0; i < ciphertext.length(); i++)
				//{
				//	printf("%02x ", (unsigned char)ciphertext[i]);
				//}
				//puts("");
				
				memcpy (packet, ciphertext.c_str(), ciphertext.length());
				length = ciphertext.length();
			}

			session_active = 1;
		}
		else
		{
			// DEBUG
			//puts("CIPHERTEXT:");
			//for (int i = 0; i < length; i++)
			//{
			//	printf("%02x ", (unsigned char)(packet[i]));
			//}
			//printf("%d\n", length);
			//puts("");
			//ciphertext = packet;

			ciphertext.assign(packet, length);
			plaintext = "";

			// Decrypt packet
			CryptoPP::StringSource( ciphertext, true,
				new CryptoPP::StreamTransformationFilter (aes_decrypt,
					new CryptoPP::StringSink( plaintext )
				)
			);
			
			strncpy (packet, plaintext.c_str(), 80);
			length = strlen(packet);

    		token = strtok(packet, tok);
			username = token;
    		token = strtok(NULL, tok);

			if (user != username)
			{
				strncpy(packet, "Invalid Request", 80);
			}
			else {
				//printf("getting mutex of %s", username);
				std::map<const std::string , pthread_mutex_t>::iterator mutex_itr = mutexs.find(username);
				pthread_mutex_lock(&(mutex_itr->second));
				//printf("got mutex of %s", username);
			
				if(!strcmp(token, "balance")){
					char* holder;
					char balance[80];
					snprintf(balance, 80,"%d", accounts[username]);
					strncpy(packet, balance, 80);
					length = strlen(packet) + 1;
					packet[length - 1] = ' ';
				}
				
				else if(!strcmp(token, "withdraw")){
					token = strtok(NULL, tok);
					amount = atoi(token);
					if(amount > 0 && itr->second >=amount){
						itr->second-=amount;
						strcpy(packet, "Confirmed");
						length = strlen("Confirmed") + 1;
						packet[length - 1] = ' ';
					}
					else{
						strcpy(packet, "Denied");
						length = strlen("Denied") + 1;
						packet[length - 1] = ' ';
					}
				}
				
				else if(!strcmp(token, "transfer")){
					token = strtok(NULL, tok);
					amount = atoi(token);
					token = strtok(NULL, tok);
					transfer_username = token;
					
					transfer_itr = accounts.find(transfer_username);
					if(transfer_itr != accounts.end() && transfer_itr != itr && amount > 0 && itr->second >=amount){
						//printf("getting mutex of %s", transfer_username);
						std::map<const std::string , pthread_mutex_t>::iterator transfer_mutex_itr = mutexs.find(transfer_username);
						pthread_mutex_lock(&(transfer_mutex_itr->second));
						//printf("got mutex of %s", transfer_username);
						itr->second-=amount;
						transfer_itr->second+=amount;
						strcpy(packet, "Confirmed");
						length = strlen("Confirmed") + 1;
						packet[length - 1] = ' ';
						pthread_mutex_unlock(&(transfer_mutex_itr->second));
						//printf("releasing mutex of %s", transfer_mutex_itr->first);
					}
					else{
						strcpy(packet, "Denied");
						length = strlen("Denied") + 1;
						packet[length - 1] = ' ';
					}
				}
				else if(!strcmp(token, "logout")){
					session_active = 0;
					user = "";
				}
				
				else{
					strcpy(packet, "Invalid Request");
					length = strlen("Invalid Request") + 1;
					packet[length - 1] = ' ';
				}
				
				pthread_mutex_unlock(&(mutex_itr->second));
				//printf("released mutex of %s", mutex_itr->first);
			}
			
			// padding: adds a space and then 'A's up to 1023 characters plus \0
			for(unsigned int i = length; i < 1023; ++i){
			  packet[i] = 'A';
			}
			packet[1023] = '\0';
			length = 1024;
			
			plaintext = packet;
			ciphertext = "";

			// Encrypt packet
			CryptoPP::StringSource( plaintext, true,
				new CryptoPP::StreamTransformationFilter (aes_encrypt,
					new CryptoPP::StringSink( ciphertext )
				)
			);
			
			memcpy (packet, ciphertext.c_str(), ciphertext.length());
			length = ciphertext.length();

			// DEBUG
			//puts("CIPHERTEXT:");
			//for (int i = 0; i < length; i++)
			//{
			//	printf("%02x ", (unsigned char)(packet[i]));
			//}
			//puts("");
		}
		
		//send the new packet back to the client
		/*TODO: need padding on packet so attacker cant see length
		otherwise he can easily know magnitude of balance, or whether request was confimed or denied. */
		/*also, maybe confimed/denied messages should be more complex, to avoid being easily faked/swapped.
		right now, any request by any user will return identical confimed/denied messages, easy to send 
		wrong message back to atm to ex. withdraw nmoney when you dont actually have enough.*/
		
	
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
		
		/*an invalid request shouldnt be possible, and will close the connection. 
		However, it needs to first communicate with the atm that the request was invalid,
		otherwise the atm waits forever for a response from the bank. Here, after sending
		the message, the connection is terminated*/
		if(!strncmp(packet, "Invalid Request", 15)){
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
			if (itr == accounts.end()) {
				printf("User: %s does not exist", username);
				continue;
			}
			//printf("getting mutex of %s", username);
			std::map<const std::string , pthread_mutex_t>::iterator mutex_itr = mutexs.find(username);
    		pthread_mutex_lock(&(mutex_itr->second));
			//printf("got mutex of %s", username);
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
				printf("Added $%d to user %s\n", amount, username);
			}
			pthread_mutex_unlock(&(mutex_itr->second));
			//printf("releasing mutex of %s", mutex_itr->first);
		}
		//balance
		else if(!strcmp(token, "balance")){
			std::map<const std::string , int>::iterator itr = accounts.find(username);
			if (itr == accounts.end()) {
				printf("User: %s does not exist", username);
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
