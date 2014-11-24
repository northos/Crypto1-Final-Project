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

	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	byte iv[CryptoPP::AES::DEFAULT_KEYLENGTH];

	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aes_decrypt;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes_encrypt;
	//CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption aes_decrypt;
	//CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption aes_encrypt;

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
		  packet[length - 1] = '\0';
		}

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
