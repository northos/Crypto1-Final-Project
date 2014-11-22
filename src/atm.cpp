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

	//input loop
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
                    }
                    else
                    {
			user = "";
                        printf("\nAccess denied\n");
                    }
                }
                  
		// balance, withdraw, or transfer
		// sends packet to bank with the username and command
		else if(!strcmp(buf, "balance") || !strncmp(buf, "withdraw", 8) || !strncmp(buf, "transfer", 8)){
		  strcpy(packet, user.c_str());
		  strcat(packet, " ");
		  strcat(packet, buf);
		  length = user.length() + strlen(buf) + 1;
		  packet[length - 1] = '\0';
		}
		/*// withdraw [amount]
		// sends packet to bank with "withdraw [username] [amount]"
		else if(!strncmp(buf, "withdraw", 8)){
		  strcpy(packet, "withdraw ");
		  strcat(packet, user.c_str());
		  strcat(packet, " ");
		  strcat(packet, buf[9]);
		  length = user.length() + strlen(buf) + 1;
		  packet[length - 1] = '\0';
		}
		// transfer [amount] [destname]
		// sends packet to bank with "transfer [username] [amount] [destname]"
		else if(!strncmp(buf, "transfer", 8)){
		  char* token = strtok(buf, " ");
		  strcpy(packet, token);
		  strcat(packet, " ");
		  strcat(packet, user.c_str());
		  strcat(packet, " ");
		  token = strtok(NULL, " ");
		  strcat(packet, token);
		  strcat(packet, " ");
		  token = strtok(NULL, " ");
		  strcat(packet, " ");
		  length = user.length() + strlen(buf) + 1;
		  packet[length - 1] = '\0';
		  }*/

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
	}

	//cleanup
	close(sock);
	return 0;
}
