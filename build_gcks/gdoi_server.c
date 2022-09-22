#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <openssl/sha.h>
#include <pthread.h>

#include <time.h>


// Custom header files  
#include "isakmp.h"
#include "auxf.h"
#include "crypto.h"
#include "gdoi.h"
#include "client.h"


uint8_t majmin = 0x10;
uint8_t flags  = 0;
uint32_t m_id = 1;


uint8_t* icookie = "XwGczY63";
uint8_t* rcookie = "r2aXMS74";

// R-GOOSE Specific configs
int id_type = 13; 			//ID_OID
int oid_length = 11;

uint8_t* oid = "1.0.62351.1";	// ISO(1).STANDARD(0).62351.GROUP_NUMBER

uint8_t* skeyid_a = "aaaaaaaa";
int skeyid_a_length = 8;



// Configurations
int udp_port = 8080;


// Global vars
client_nd client_list = NULL;

KEKPolicy_nd sa_kek = NULL;
TEKPolicy_nd sa_tek = NULL;

int debug = 1;

int sockfd; 


void send_to_client(client_nd client, char* message,int sockfd){
	// Respond to client
	char *response = "response inside function";
	sendto(sockfd, (const char *)response, strlen(message), MSG_CONFIRM, (const struct sockaddr *) &client->client_data.c_addr, sizeof(client->client_data.c_addr));
	printf("[GCKS response]: %s\n", response);
}


int process_gk_pull_m1_state(client_nd client, char message[MAXLINE], int sockfd, int packet_length){
	// GK-PULL Message 3 received

	// Process Message 3
	int gdoi_res = gdoi_process_groupkeypull_m3(message, icookie, rcookie, skeyid_a, skeyid_a_length, m_id, client->client_data.ni, client->client_data.ni_length, client->client_data.nr, client->client_data.nr_length);
	if(gdoi_res != 0){
		return -1;
	}

	// Generate Message 4
	uint8_t* m4 = NULL;
	
	uint8_t* tmpM = NULL;
	int tmpM_len = crypto_generateNonceByteStream(32, &tmpM);

	uint8_t* seq_payload = NULL;
	int seq_length = 0;
	
	uint8_t* kd_payload = NULL;
	int kd_length;
	
	uint8_t* key_packets = NULL;
	int key_packets_size;

	printf("Aqui\n");

	// TODO: FIX SPI * KEY DATA
	key_packets_size = gdoi_createKeyPacket_KEK(KD_KEK, 1, 0x01, tmpM_len, tmpM, 0, NULL, &key_packets, 0);
	
	printf("Aqui1\n");

	kd_length = gdoi_createKD_Payload(NP_LASTPAYLOAD, 1, key_packets, key_packets_size, &kd_payload);
	
	printf("Aqui2\n");
	
	// Create KeyPackets
	
	
	// Create KD Payload
	int m4_len = gdoi_create_groupkeypull_m4(icookie, rcookie, skeyid_a, skeyid_a_length, m_id, client->client_data.ni, client->client_data.ni_length, client->client_data.nr, client->client_data.nr_length, seq_payload, seq_length, kd_payload, kd_length, &m4, debug);


	sendto(sockfd, m4, m4_len, 
	MSG_CONFIRM, (const struct sockaddr *) &client->client_data.c_addr,  
		sizeof(client->client_data.c_addr));


	printf("[GCKS]: New SA2 (KEK) Key distributed to %s\n", client->client_data.c_ip);
	printf("\tKey: ");
	for(int ind = 0; ind < 32; ind++){
		printf("%02x", m4[ind]);
	}
	printf("\n");

	client->client_data.state = STATE_IDLE;
	
}


int process_idle_state(client_nd client, char message[MAXLINE], int sockfd, int packet_length){
	
	int extype;
		
	// Generic header validation
	// Packet length validation
	int res = validate_isakmphdr_packetlength(message, packet_length);
	if(res != 0){
		// Error validating packet length
		printf("Erro validar packet length\n");
		return -1;
	}
	
	// Validate ISAKMP Header
	extype = validate_isakmp_hdr(message, majmin, icookie, rcookie, flags, m_id);
	
	if(extype == -1){
		// Error Validating ISAKMP Header
		printf("Erro validar packet isakmp header\n");
		return -1;
	}
	
	if(extype == ET_GROUPKEY_PULL){
				
		// Message is ExType GroupKey-PULL
		uint8_t* group_id = NULL;
		int group_id_length = 0;

		//TODO: Change Group ID to specific to user
		int gdoi_res = gdoi_process_groupkeypull_m1(message, icookie, rcookie, skeyid_a, skeyid_a_length, m_id, &client->client_data.ni, &client->client_data.ni_length, &group_id, &group_id_length);
		if(gdoi_res != 0){
			return -1;
		}

		printf("[GCKS]: Client with IP %s on port %d Initiated new GK-PULL Exchange\n", client->client_data.c_ip, client->client_data.c_port);
		
		// Verify database for GroupID and check access authorization for c_id to GroupID
		// TODO ...
		
		// Build up GroupKey-PULL Message 2 - HDR, HASH(2), Nr, SA
		uint8_t* m2 = NULL;

		int m2_len = gdoi_create_groupkeypull_m2(icookie, rcookie, skeyid_a, skeyid_a_length, m_id, client->client_data.ni, client->client_data.ni_length, DOI_GDOI, 0, NP_SAKEK, sa_kek, NULL, &client->client_data.gdoi_gm, &m2, &client->client_data.nr, &client->client_data.nr_length, debug);
		
		sendto(sockfd, m2, m2_len, 
		MSG_CONFIRM, (const struct sockaddr *) &client->client_data.c_addr,  
			sizeof(client->client_data.c_addr));

		// Update client status
		client->client_data.state = STATE_GK_PULL_M1;
		return 0;
		
	}else{
		// Other ExType - Should be DELETE message
		return -1;
	}
	
}


int process_message(client_nd client, char message[MAXLINE], int sockfd, int packet_length){
	
	if(client->client_data.authenticated == 0){
		// Needs to authenticate
	}else if(client->client_data.protocol == 1){
		// Already authenticated - GDOI Protocol
		if(client->client_data.state == STATE_IDLE){
			// Client was idle 
			// Only accept 1st GroupKey-PULL message or DELETE/EXIT/REMOVE
			int res = process_idle_state(client, message, sockfd, packet_length);
			return res;
		}else if(client->client_data.state == STATE_GK_PULL_M1){
			// GroupKey-PULL 
			int res = process_gk_pull_m1_state(client, message, sockfd, packet_length);
			return res;
		}else{
			// Unknown behavior
			perror("Process Message -> GDOI -> State = Unknown behavior\n");
			return -1;
		}
	}else{
		// Unknown behavior
		perror("Process Message -> Protocol = Unknown behavior\n");
		return -1;
	}
}


void *commandline_thread(void *vargp){
	
	char *cmd;
	size_t bufsize = 100;
	
	while(1){
		printf("Command: ");
		getline(&cmd, &bufsize, stdin);
		
		if(strcmp(cmd, "rekey\n") == 0){
			// Init rekey alg
			client_nd tmp = client_list;

			uint8_t* new_tek = NULL;
			int new_tek_len = crypto_generateNonceByteStream(32, &new_tek);


			while(tmp != NULL){
				sendto(sockfd, new_tek, new_tek_len, 
				MSG_CONFIRM, (const struct sockaddr *) &tmp->client_data.c_addr,  
					sizeof(tmp->client_data.c_addr));
				tmp = tmp->next;
			}


		}
	}
	
	return NULL;
}



// Driver code 
int main() { 


	/*
	uint16_t a = 2;

	for (int i = 15; 0 <= i; i--) {
		printf("%c", (a & (1 << i)) ? '1' : '0');
	}

	a = modify2Byte(a, 15, 1);

	printf("\n\n");

	for (int i = 15; 0 <= i; i--) {
		printf("%c", (a & (1 << i)) ? '1' : '0');
	}


	if(checkIfBitIsSet(a,15)){
		printf("true\n");
	}else{
		printf("false\n");
	}*/



	// Initial configurations
	
	printf("GCKS is starting...\n");
	
	pthread_t cmdline_id;
	
	pthread_create(&cmdline_id, NULL, commandline_thread, NULL);
	
	// TO CHANGE
	sa_kek = (KEKPolicy_nd)malloc(sizeof(ListNode_sakek_policy));
	if(sa_kek != NULL){
		sa_kek->KEK_Policy.kek_management_algorithm = -1;
		
		sa_kek->KEK_Policy.kek_algorithm = 3;
		sa_kek->KEK_Policy.kek_key_length = 32;
		sa_kek->KEK_Policy.kek_key_lifetime = 3200;
		sa_kek->KEK_Policy.sig_hash_algorithm = 3;
		sa_kek->KEK_Policy.sig_algorithm = 2;
		sa_kek->KEK_Policy.sig_key_length = 32;
	}	

	
	
	// Set up clients linked list 
	client_list = init_clients_list();
	if(client_list == NULL){
		printf("error client list\n");
	}
	
	// Main Thread - Listen for UDP Datagram
    
    struct sockaddr_in servaddr, cliaddr; 
      
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
      
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
	
    // Filling server information 
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(udp_port); 
      
    // Bind the socket with the server address 
    if ( bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) 
    {
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    }
    
	
	while(1){
		int len, n; 
		char buffer[MAXLINE]; 

		len = sizeof(cliaddr);  //len is value/resuslt 
	  	
		n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len);
		if(n > MAXLINE){
			printf("recvfrom len of message error - too big\n");
			continue;
		}
		
		buffer[n] = '\0'; 
		
		printf("[GCKS]: New datagram received\n");  
	
		// TODO - Pool of threads
		
		// Identify client - Wrap to external function
		client_nd dest;
		
		if(search_client_by_ip_port(client_list, inet_ntoa(cliaddr.sin_addr), (int) ntohs(cliaddr.sin_port), &dest) == 0){
			// New client - Authentication (and Identification)
			printf("[GCKS]: Client not found - New client\n"); 
			client_nd dest;
			int res_c = create_new_client(client_list, inet_ntoa(cliaddr.sin_addr), (int) ntohs(cliaddr.sin_port), cliaddr, 1, 1, 1, STATE_IDLE, &dest);
			if(res_c == -1){
				printf("error creating client\n");
				continue;
			}
			
			printf("[GCKS]: Connection registered\n");
			print_client_data(dest);
			
			if(dest == NULL){
				printf("error looking for client\n");
				continue;
			}
			
			// Process client request
			int res = process_message(dest, buffer, sockfd, n);
		
		}else{
			if(dest != NULL){
				// Connection already exists
				printf("[GCKS]: Connection found\n");
				
				print_client_data(dest);
				
				int res = process_message(dest, buffer, sockfd, n);
			}else{
				printf("error looking for client\n");
			}
		}

		/* Termination condition */
		/*if ...
			break;
		*/
		// Clear buffer
		memset(buffer, 0, MAXLINE);
		
	}
	
	pthread_join(cmdline_id, NULL);
      
    return 0; 
} 
