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
#include "client.h"
#include "gdoi.h"


// Security Association Stuff 
int hash_alg = 1;


// Configurations
int gcks_port = 8080;
char* gcks_ip = "localhost";

int gm_port = 8081;

uint8_t* icookie = "XwGczY63";
uint8_t* rcookie = "r2aXMS74";

uint32_t m_id = 1;

int keytimelife = 5;

// R-GOOSE Specific configs
int id_type = 13; 			//ID_OID
int oid_length = 11;

uint8_t* oid = "1.0.62351.1";	// ISO(1).STANDARD(0).62351.GROUP_NUMBER

uint8_t* skeyid_a = "aaaaaaaa";
int skeyid_a_length = 8;

int debug = 0;

int ni_length = -1;
uint8_t* ni = NULL;

int sockfd; 
struct sockaddr_in     servaddr; 

Phase1SA phase1_sa;
GroupMember gdoi_gm;

KEKPolicy_nd kek_policy;
TEKPolicy_nd tek_policy;

int current_state = 0;


int execute_groupkeypull(int sockfd, struct sockaddr_in servaddr){
	
	// Create GroupKey-PULL Message 1

	uint8_t* m1 = NULL;
	
	int res = gdoi_create_groupkeypull_m1(icookie, rcookie, skeyid_a, skeyid_a_length, m_id, oid, oid_length, id_type, &m1, &ni, &ni_length, debug);
	
	// Send GroupKey-PULL Message 1

	sendto(sockfd, m1, res, 
		MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
			sizeof(servaddr)); 
	

	current_state = 1;
	
	
}


int process_message_gm(int sockfd, struct sockaddr_in servaddr, unsigned char rec_m[MAXLINE], int rec_m_len){
	if(current_state == 0){
		// rekey message
		
		/*
		printf("[GM]: Other GM disconnected. Renewing GroupKey (TEK).\n");
		printf("\tNew TEK: ");
		for(int ind = 0; ind < rec_m_len; ind++){
			printf("%02x", rec_m[ind]);
		}
		printf("\n");
		*/

	}else if(current_state == 1){
		// Expecting GroupKey-PULL Message 2 (from GCKS)


	    // Process GroupKey-PULL Message 2

		uint8_t* nr = NULL;
		int nr_length = 0;

	    int gdoi_res = gdoi_process_groupkeypull_m2(rec_m, icookie, rcookie, skeyid_a, skeyid_a_length, m_id, ni, ni_length, &nr, &nr_length, &kek_policy, &tek_policy, &gdoi_gm);

		// Send Message 3

	    // TODO: AQUIIII
		

		uint8_t* m3 = NULL;

		int res = gdoi_create_groupkeypull_m3(icookie, rcookie, skeyid_a, skeyid_a_length, m_id, ni, ni_length, nr, nr_length, &m3, debug);

		printf("M3: ");
		for(int ind = 0; ind < res; ind++){
			printf("%02x", m3[ind]);
		}
		printf("\n");

		sendto(sockfd, m3, res, 
			MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
				sizeof(servaddr)); 
				
		

		current_state = 2;

	}else if(current_state == 2){
		// receive m4

	    printf("[GM]: New SA2 (KEK) Key received.\n");
		printf("\tKey: ");
		for(int ind = 0; ind < rec_m_len; ind++){
			printf("%02x", rec_m[ind]);
		}
		printf("\n");

		printPayload(gdoi_gm.kek->kek_sa.spi, 16);

		current_state = 0;

	}

}



void *receiver_thread(void *vargp){
	
	sleep(1);

    while(1){
    	printf("[GM]: Initiating GK-PULL - Retrieve new KEK SA\n");
		int res = execute_groupkeypull(sockfd, servaddr);
		sleep(keytimelife);
	}

	
	return NULL;
}



  
// Driver code 
int main(int argc, char **argv) { 
    char buffer[MAXLINE]; 
    char *request = "request"; 


    pthread_t receiver_id;
	
	pthread_create(&receiver_id, NULL, receiver_thread, NULL);


	if(argc == 2){
		gm_port = atoi(argv[1]);
	}else{
		printf("Error Initiating client. Missing port.\n");
		return -1;
	}


    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
  
    memset(&servaddr, 0, sizeof(servaddr)); 
      
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(gcks_port); 
    servaddr.sin_addr.s_addr = INADDR_ANY;
    
    int n, len; 
    


    //aqiui
    struct sockaddr_in cliaddr; 
      
      
    memset(&cliaddr, 0, sizeof(cliaddr)); 
	
    // Filling server information 
    cliaddr.sin_family    = AF_INET; // IPv4 
    cliaddr.sin_addr.s_addr = INADDR_ANY; 
    cliaddr.sin_port = htons(gm_port); 
      
    // Bind the socket with the server address 
    if ( bind(sockfd, (const struct sockaddr *)&cliaddr, sizeof(cliaddr)) < 0 ) 
    {
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    }

    //aqiu



          
    /*n = recvfrom(sockfd, (char *)buffer, MAXLINE,  
                MSG_WAITALL, (struct sockaddr *) &servaddr, 
                &len); 
    buffer[n] = '\0'; 
    printf("GCKS response: %s\n", buffer); 
	
	// 2nd message
	
	sendto(sockfd, (const char *)request, strlen(request), 
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
            sizeof(servaddr)); 
    
	printf("[GM request]: %s\n", request); 
          
    n = recvfrom(sockfd, (char *)buffer, MAXLINE,  
                MSG_WAITALL, (struct sockaddr *) &servaddr, 
                &len); 
    buffer[n] = '\0'; 
    printf("GCKS response: %s\n", buffer); */
	

	// Init protocol - GroupKey PULL

	//printf("[GM]: Initiating GK-PULL - Retrieve new KEK SA\n");
	//int res = execute_groupkeypull(sockfd, servaddr);
	//printf("[GM]: GK-PULL Protocol terminated\n");
	
	while(1){

		struct sockaddr_in     recvd; 
		memset(&recvd, 0, sizeof(recvd)); 

		unsigned char rec_m[MAXLINE];
		int rec_m_len;
		
		int len = sizeof(recvd);
		
		rec_m_len = recvfrom(sockfd, (char *)rec_m, MAXLINE,  
	                MSG_WAITALL, (struct sockaddr *) &recvd, 
	                &len); 
	    rec_m[rec_m_len] = '\0';

	    int res = process_message_gm(sockfd, servaddr, rec_m, rec_m_len);

	}
	
    close(sockfd); 

    pthread_join(receiver_id, NULL);

    return 0; 
} 
