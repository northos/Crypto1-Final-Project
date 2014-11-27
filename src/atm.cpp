/**
	@file atm.cpp
	@brief Top level ATM implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "cryptopp/aes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/ccm.h"
#include "cryptopp/rsa.h"

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}

	//socket setup
	unsigned short proxport = atoi(argv[1]);
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!sock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(proxport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
	{
		printf("fail to connect to proxy\n");
		return -1;
	}

	std::string plaintext, ciphertext;

	CryptoPP::AutoSeededRandomPool rng;

	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	byte iv[CryptoPP::AES::DEFAULT_KEYLENGTH];

	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aes_decrypt;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes_encrypt;

	CryptoPP::Integer bank_modulus(	"0xbbed02f6dbb34c5aa313b9d6e54b3e862e0bd1d8d0d9b608cff72b5439ba40b0\
					   4c1aab93a17e176cd56ba2626f25f25160f51940c9299347f1adffb22192e20a\
					   e3b5205a2565b654a123914ada58946be5a16c9e070f90e25996efd8350b76eb\
					   197decf7aebe8c591ad2f3999ae125f8ad35b2b258b7e4134bf19aa803a8edf0\
					   533921256607dad00e6ddc3e1b78f4df3ff7918590a59a6cb2aded1a708cffca\
					   906abbea826f4973dc9d37e74d4e01d1b95f1e7abc425127178a3eb22dc03940\
					   4ed2bcd574954465c94af3a49ec6237ef8991c51b20ff8a818dba5149afae651\
					   11211f1a806526e62b3cbb852683f9d04981fddc5d10ed652cbc104cdf8b1be5");
	CryptoPP::Integer bank_pub_key( "0x11");

	CryptoPP::Integer atm_modulus(	"0xe702c9e39c8deea1f2496b5535acc7839819c7e3b1124d360b4b33141db5632a\
					   f648c5da27708bd7f5f5f8d8f32e15960c4791d43ec92906a528157398695379\
					   037a9bfd0c580c276d37257a5c264a633f3fe4e16299177a1c4e54c2afa52103\
					   04f948853a986c14e6124ac7849c61a17f67666017d3f2e84666c329fff1a85b\
					   439c7f42dfbdc51e7b020fce5412eb087e1afc3c36c14523a4c714d169eec7f6\
					   6d42d97688aafbe12151de9fca9e26c91b7c424d02afe2533bfb26b88f850171\
					   c2629dd4f8268dc7daf7643d59997228c2cf25232f20f0b0d0536b6e92322cd1\
					   68d66d6708efa17a3747e6c72f1ecd84bfdc4e7979bf2653c4af23a792d2f86b");

	CryptoPP::Integer atm_priv_key(	"0x11aa60c19804d481d7cc64110ea54e81071d13cda5a2876906e31d8189cd1e2b\
					   f1b43f516f70832a1d59960a911719beac9c0fab561e711112a734d725414722\
					   da9e75571d8e43303102b610e2e7d27d0c5dbbaad5d881cb98c0b82d0162767a\
					   351613193f35d20da52b9042750ef8683569ca166838ddde8fecc09e5150388b\
					   59f42b53cb20f9c271a6bd10d5781aa8091b70f7601a7b909c49e03d70a4a344\
					   a69f5837c93750d474513086442143bc5b2ec308380ccc679cb0e9a014429340\
					   271a96d9a4a5350c7a1685ec21c3643ff9fd73dcd7951a0a4588d3e10f297d85\
					   59b0e97f146322702ab8532d56d1155f000d1fb733cc402045cedd32a9f2a6e5");
	CryptoPP::Integer atm_pub_key(  "0x11");

	CryptoPP::RSA::PrivateKey privkey;
	CryptoPP::RSA::PublicKey pubkey;
	privkey.Initialize(atm_modulus, atm_pub_key, atm_priv_key);
	pubkey.Initialize(bank_modulus, bank_pub_key);
	CryptoPP::RSAES_OAEP_SHA_Encryptor rsa_encrypt (pubkey);
	CryptoPP::RSAES_OAEP_SHA_Decryptor rsa_decrypt (privkey);

	//input loop
	unsigned char session_active = 0;
	char buf[80];
	std::string user = "";  // current logged-in user
	while(1)
	{
		printf("atm> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline

		//TODO: your input parsing code has to put data here
		char packet[1024];
		int length = 1;

		//input parsing
		//logout
		if(!strcmp(buf, "logout")){
		  user = "";
		  break;
		}

		//login [username]
		else if(!strncmp(buf, "login", 5)){
			// ignore if already logged in
			if(user != ""){
				printf("\n%s already logged in.\n", user.c_str());
				continue;
			}
                	
                	char username[80];
                	char card_filename[80];
                	strncpy(username, buf + 6, 74);
                	strncpy(card_filename, buf + 6, 74);
                	strncpy(card_filename + strlen(username), ".card\0", 6);
                	
                	FILE *card = fopen(card_filename, "r");
                	
                	if (card == NULL)
                	{
                		printf("\nUser does not exist\n");
                		continue;
                	}
                	
                	// Fetching pin from card
                	unsigned int pin;
                	fread(&pin, sizeof(unsigned int), 1, card);
                	fclose(card);
                	
// Remove before submission
printf("%d\n", pin);
			unsigned char valid_pin = 0;
			
			for (int i = 3; i > 0; --i)
			{
				printf("\nPlease enter your pin: ");
				fgets(buf, 79, stdin);
				buf[strlen(buf) - 1] = '\0';
				unsigned int pin_entry = atoi(buf);
				
				if (pin_entry == pin)
				{
					valid_pin = 1;
					break;
				}
				printf("\nIncorrect pin, please try again. (%d tries remaining)", i-1);
			}
			
			if (valid_pin)
			{
				user = username;
				printf("\nEstablishing session\n");

				strncpy (packet, "open ", 80);
				strncat (packet, user.c_str(), 76);
				length = strlen(packet);
			}
			else
			{
				user = "";
				printf("\nAccess denied\n");
				continue;
			}

               }
                  
		// balance, withdraw, or transfer
		// sends packet to bank with the username and command
		else if(!strcmp(buf, "balance") || !strncmp(buf, "withdraw", 8) || !strncmp(buf, "transfer", 8) || !strncmp(buf, "logout", 6)){
		  strcpy(packet, user.c_str());
		  strcat(packet, " ");
		  strcat(packet, buf);
		  length = user.length() + strlen(buf) + 2;
		}

		// padding: adds a space and then 'A's up to 1023 characters plus \0
		packet[length - 1] = ' ';
		for(unsigned int i = length; i < 1023; ++i){
		  packet[i] = 'A';
		}
		packet[1023] = '\0';

		if (session_active)
		{
			plaintext.assign(packet, length);
			ciphertext = "";

			// Encrypt Packet
			CryptoPP::StringSource( plaintext, true,
				new CryptoPP::StreamTransformationFilter (aes_encrypt,
					new CryptoPP::StringSink( ciphertext )
				)
			);

			memcpy(packet, ciphertext.c_str(), ciphertext.length());
			length = ciphertext.length();

			// DEBUG
			//for (int i = 0; i < length; i++)
			//{
			//	printf("%02x ", (unsigned char)(packet[i]));
			//}

			//puts("");
			//printf("%d\n", length);
		}


		//send the packet through the proxy to the bank
		if(sizeof(int) != send(sock, &length, sizeof(int), 0))
		{
			printf("fail to send packet length\n");
			break;
		}
		if(length != send(sock, (void*)packet, length, 0))
		{
			printf("fail to send packet\n");
			break;
		}

		//TODO: do something with response packet
		if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
		{
			printf("fail to read packet length\n");
			break;
		}
		if(length >= 1024)
		{
			printf("packet too long\n");
			break;
		}
		if(length != recv(sock, packet, length, 0))
		{
		        printf("fail to read packet\n");
			break;
		}

		if (!session_active)
		{

			// DEBUG
			//puts("rsa ciphertext:");
			//for (int i = 0; i < length; i++)
			//{
			//	printf("%02x ", (unsigned char)packet[i]);
			//}
			//puts("");
			//printf("%d\n", length);

			ciphertext.assign(packet, length);

			CryptoPP::StringSource(ciphertext, true,
				new CryptoPP::PK_DecryptorFilter(rng, rsa_decrypt,
					new CryptoPP::StringSink(plaintext)
				)
			);
			
			memcpy (packet, plaintext.c_str(), plaintext.length());
			length = ciphertext.length();

			memcpy(key, packet, 16);
			memcpy(iv, packet+16, 16);
				
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

			// Setup aes cipher for encryption and decryption
			aes_encrypt.SetKeyWithIV(key, sizeof(key), iv);
			aes_decrypt.SetKeyWithIV(key, sizeof(key), iv);

			session_active = 1;
		}
		else
		{
			ciphertext.assign(packet, length);
			plaintext = "";

			// DEBUG
			//puts("CIPHERTEXT:");
			//for (int i = 0; i < length; i++)
			//{
			//	printf("%02x ", (unsigned char)(packet[i]));
			//}
			//puts("");

			// Decrypt Packet
			CryptoPP::StringSource( ciphertext, true,
				new CryptoPP::StreamTransformationFilter (aes_decrypt,
					new CryptoPP::StringSink( plaintext )
				)
			);
			
			strncpy(packet, plaintext.c_str(), 80);
			puts(packet);
		}
	}

	//cleanup
	close(sock);
	return 0;
}
