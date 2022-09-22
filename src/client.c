#include "client.h"

int create_new_client(client_nd head, char ip[], int port, struct sockaddr_in sock_addr, int status, int authenticated, int protocol, int state, client_nd *dest){
	// Allocate space for new node
	client_nd new_client = (client_nd)malloc(sizeof(ListNode_client));
	
	if(new_client == NULL){
		printf("Malloc error - Memory exausted\n");
		return -1;
	}
	
	// Populate new node with client data
	strcpy(new_client->client_data.c_ip, ip);
	new_client->client_data.c_port = port;
	new_client->client_data.c_addr = sock_addr;
	new_client->client_data.status = status;
	new_client->client_data.authenticated = authenticated;
	new_client->client_data.protocol = protocol;
	new_client->client_data.state = state;
	
	// Null all Security Associations
	new_client->client_data.phase1_sa.initialized = 0;
	new_client->client_data.gdoi_gm.initialized = 0;

	new_client->client_data.ni = NULL;
	new_client->client_data.ni_length = -1;

	new_client->client_data.nr = NULL;
	new_client->client_data.nr_length = -1;
		
	// Append to client list
	client_nd tmp = head;
	

	while(tmp->next != NULL){
		tmp = tmp->next;
	}
	
	tmp->next = new_client;
	tmp->next->next = NULL;
	
	(*dest) = tmp->next;

	return 1;
}

void print_client_data(client_nd client){
	printf("\tIP: %s\n", client->client_data.c_ip);
	printf("\tPort: %d\n", client->client_data.c_port);
	printf("\tAuthenticated: %d\n", client->client_data.authenticated);
	printf("\tState - Protocol: %d\n", client->client_data.protocol);
	printf("\tState: %d\n", client->client_data.state);
}

void print_client_list(client_nd head){
	client_nd tmp = head;
	int i = 0;
	
	if(tmp == NULL){
		printf("deu merda\n");
	}
	
	while(tmp->next != NULL){
		printf("[Client #%d]\n", i);
		print_client_data(tmp->next);
		printf("\n");
		tmp = tmp->next;
		i++;
	}
	
	
}

client_nd init_clients_list(){
	client_nd head;
	head = (client_nd)malloc(sizeof(ListNode_client));
	if(head != NULL){
		strcpy(head->client_data.c_ip, "-1");
		head->client_data.c_port = -1;
		head->client_data.status = -1;
		head->client_data.authenticated = -1;
		head->client_data.protocol = -1;
		head->client_data.state = -1;
		
		// Null all Security Associations
		head->client_data.phase1_sa.initialized = -1;
		head->client_data.gdoi_gm.initialized = -1;

		head->client_data.ni = NULL;
		head->client_data.ni_length = -1;

		head->client_data.nr = NULL;
		head->client_data.nr_length = -1;
		
		return head; 
	}
	return NULL;
}

int search_client_by_ip_port(client_nd head, char ipaddr[], int port, client_nd *dest){
	*dest = head->next;
	
	while((*dest) != NULL){
		if((strcmp((*dest)->client_data.c_ip, ipaddr) == 0) && (*dest)->client_data.c_port == port){
			return 1; 
		}
		*dest = (*dest)->next;
	}
	return 0;
}


