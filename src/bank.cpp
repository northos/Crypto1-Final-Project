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

#include <map>
#include <iostream>

 /*string is USERNAME, int is BALANCE. */
 /* The PINS are no longer stored in the bank, as only the atm needs theml. Now the key is just the username, much simpler*/
std::map<const std::string , int> accounts;

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
	int amount;
	std::map<const std::string , int>::iterator itr;
	std::map<const std::string , int>::iterator transfer_itr;
	char* transfer_username;
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
		
		//process packet data
    		token = strtok(packet, tok);
    		username = token;
		//verify username exists
    		itr = accounts.find(username);
    		if(itr == accounts.end()){
    			printf("User %s does not exist!\n", username);
    			break;
    		}
    		
    		token = strtok(NULL, tok);
    		
		if(!strcmp(token, "balance")){
			char* holder;
			
			//TODO: dont use itoa, change method of conversion
			//itoa(itr->second,holder,10); 
			
			strcpy(packet, holder);
			length = strlen(holder) + 1;
			packet[length - 1] = '\0';
		}
		
		else if(!strcmp(token, "withdraw")){
			token = strtok(NULL, tok);
			amount = atoi(token);
			if(amount > 0 && itr->second >=amount){
				itr->second-=amount;
				strcpy(packet, "Confirmed");
				length = strlen("Confirmed") + 1;
				packet[length - 1] = '\0';
			}
			else{
				strcpy(packet, "Denied");
				length = strlen("Denied") + 1;
				packet[length - 1] = '\0';
			}
		}
		
		else if(!strcmp(token, "transfer")){
			token = strtok(NULL, tok);
			amount = atoi(token);
			token = strtok(NULL, tok);
			transfer_username = token;
			
			transfer_itr = accounts.find(transfer_username);
    			if(transfer_itr != accounts.end() && transfer_itr != itr && amount > 0 && itr->second >=amount){
				itr->second-=amount;
				transfer_itr->second+=amount;
				strcpy(packet, "Confirmed");
				length = strlen("Confirmed") + 1;
				packet[length - 1] = '\0';
	    		}
	    		else{
				strcpy(packet, "Denied");
				length = strlen("Denied") + 1;
				packet[length - 1] = '\0';
	    		}
		}
		
		else{
			strcpy(packet, "Invalid Command");
			length = strlen("Invalid Command") + 1;
			packet[length - 1] = '\0';
		}
		
		//send the new packet back to the client
		/*TODO: need padding on packet so attacker cant see length
		otherwise he can easily know magnitude of balance, or whether request was confimed or denied. */
		/*also, maybe confimed/denied messages should be more complex, to avoid being easily faked/swapped.
		right now, any request by any user will return identical confimed/denied messages, easy to send 
		wrong message back to atm to ex. withdraw nmoney when you dont actually have enough.*/
		
		if(sizeof(int) != send(csock, &length, sizeof(int), 0))
		{
			printf("[bank] fail to send packet length\n");
			break;
		}
		if(length != send(csock, (void*)packet, length, 0))
		{
			printf("[bank] fail to send packet\n");
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
	while(1)
	{
		printf("bank> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
		//TODO: your input parsing code has to go here

		token = strtok(buf, tok);
		
		//deposit
		if(!strcmp(token, "deposit")){
		  // TODO: deposit code
		  //get user
		  //add balance
		}
		//balance
		if(!strcmp(token, "balance")){
		  // TODO: balance code
		}
	}
}
