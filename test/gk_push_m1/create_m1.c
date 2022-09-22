#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <openssl/sha.h>

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
int udp_port = 8080;
int gcks_ip = "localhost";

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

int debug = 1;


int main(){
	
	uint8_t* m1 = NULL;
	
	int res = create_groupkeypull_m1(icookie, rcookie, skeyid_a, skeyid_a_length, m_id, oid, oid_length, id_type, &m1, debug);
	
	printf("size = %d\n%", res);
	
	printPayload(m1, res);
	
	return 0;
}