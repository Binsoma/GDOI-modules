#ifndef CLIENT_H__
#define CLIENT_H__


#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#include "sa.h"



// GCKS Client Internal States
#define STATE_IDLE			0

#define STATE_1				1		// GK-PULL M1 was received, waiting for M3

#define STATE_GK_PULL_M1	1
#define STATE_GK_PULL_M2	2
#define STATE_GK_PULL_M3	3
#define STATE_GK_PULL_M4	4



// General Server configs - for now static
#define INIT_CLIENTS 2

typedef struct client_node* client_nd;

// Struct Client - keep track UDP clients
typedef struct Client_info{
	// Client Identity - other info?
	char c_ip[INET_ADDRSTRLEN];
	int c_port;
	
	// Client ADDR info
	struct sockaddr_in c_addr;
	
	int status;
	
	int authenticated;						// indicates if client is authenticated
	
	int protocol;							// 0 - ISAKMP; 1 - GDOI 
	int state;								// State of the protocol
	
	// Security Related Info
	Phase1SA phase1_sa;
	GroupMember gdoi_gm;

	// TODO: List of Ni/Nr associated with M-ID
	uint8_t* ni;
	int ni_length;

	uint8_t* nr;
	int nr_length;
	
} Client;


// Client Linked List struct
typedef struct client_node {
	Client client_data;
	client_nd next;
} ListNode_client;


int create_new_client(client_nd head, char ip[], int port, struct sockaddr_in sock_addr, int status, int authenticated, int protocol, int state, client_nd *dest);
void print_client_data(client_nd client);
void print_client_list(client_nd head);
client_nd init_clients_list();
int search_client_by_ip_port(client_nd head, char ipaddr[], int port, client_nd *dest);




#endif /* client.h */
