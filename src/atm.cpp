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
#include "cryptopp/pssr.h"

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

	std::string plaintext, ciphertext, signature;

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
	CryptoPP::Integer atm_priv_key(	"0x1b20971a9c6ce2f2e59af5fdcfa8d58e59377d79a0f8a5fff690a780efd9152258\
					   326f1b89f8ce597d55a030de336362c04e166808e9a5c03a6e6062d3ec9c68f8bc\
					   3e019577e990656704d2482d27f931c75a3cc480131b2db2119b5fede9cce13677\
					   eb6d205694e0b5d690160e9ea30114964a2cd81e94f5b32220624acaeed546d4af\
					   7baafdd66839c34464ed4b46e35fdcf551c6ecd4b650678dd70addeb90984c78f9\
					   12b1a8de42939762cc0f53e9d2a7c054b9c695177a37ff623f9d1639a6ed913bd6\
					   acc8d649c09b02015eb4221606edc226402ed35333ea68c5ba83436c9a9f35b771\
					   bfeb59371d90efd88c03c0df87881c1c473cd5750d9fb603e44193a23654e26bc1\
					   340283cb19f042263cc0fe90bf6de06a73b2c948539ac3b39313f7241bbf261b21\
					   45316550207ba6cc392b955dd418030258b8bbd8d2ce03664928028191a99f9f7e\
					   e4c32a268f812eb387e3499ead2f5e4f6f680291");
	CryptoPP::Integer atm_pub_key(	"0x11");

	CryptoPP::RSA::PrivateKey privkey;
	CryptoPP::RSA::PublicKey pubkey;
	privkey.Initialize(atm_modulus, atm_pub_key, atm_priv_key);
	pubkey.Initialize(bank_modulus, bank_pub_key);
	//CryptoPP::RSAES_OAEP_SHA_Encryptor rsa_encrypt (pubkey);
	CryptoPP::RSASS<CryptoPP::PSS,CryptoPP::SHA1>::Verifier rsa_sha_verify (pubkey);
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
		else if(!strcmp(buf, "balance") || !strncmp(buf, "withdraw", 8) || !strncmp(buf, "transfer", 8) || !strncmp(buf, "logout", 6))
		{
			strcpy(packet, user.c_str());
			strcat(packet, " ");
			strcat(packet, buf);
			length = user.length() + strlen(buf) + 2;
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

			// DEBUG
			//puts("rsa ciphertext:");
			//for (int i = 0; i < length; i++)
			//{
			//	printf("%02x ", (unsigned char)packet[i]);
			//}
			//puts("");
			//printf("%d\n", length);

			ciphertext = "";
			plaintext = "";
			signature = "";
			ciphertext.assign(packet, length);

			CryptoPP::StringSource(ciphertext, true,
				new CryptoPP::PK_DecryptorFilter(rng, rsa_decrypt,
					new CryptoPP::StringSink(signature)
				)
			);

			try
			{
				CryptoPP::StringSource(signature, true,
					new CryptoPP::SignatureVerificationFilter(
						rsa_sha_verify,
						new CryptoPP::StringSink(plaintext),
						CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION |
						CryptoPP::SignatureVerificationFilter::PUT_MESSAGE
					)
				);
			}
			catch(CryptoPP::SignatureVerificationFilter::SignatureVerificationFailed)
			{
				puts("Invalid cryptographic signature detected!");
				continue;
			}
			
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
