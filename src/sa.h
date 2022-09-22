#ifndef SA_H__
#define SA_H__

#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <netinet/in.h> 

// KEK Attributes -> Type - write this to packet
#define KEK_MANAGEMENT_ALGORITHM	1
#define KEK_ALGORITHM				2
#define KEK_KEY_LENGTH				3
#define KEK_KEY_LIFETIME			4
#define SIG_HASH_ALGORITHM			5
#define SIG_ALGORITHM               6
#define SIG_KEY_LENGTH				7

// KEK Attributes -> KEK_MANAGEMENT_ALGORITHM
#define LKH							1

// KEK Attributes -> KEK_ALGORITHM
#define KEK_ALG_DES					1
#define KEK_ALG_3DES 				2
#define KEK_ALG_AES					3

// KEK Attributes -> SIG_HASH_ALGORITHM
#define SIG_HASH_MD5				1
#define SIG_HASH_SHA1				2
#define SIG_HASH_SHA256				3
#define SIG_HASH_SHA384				4
#define SIG_HASH_SHA512				5

// KEK Attributes -> SIG_ALGORITHM
#define SIG_ALG_RSA					1
#define SIG_ALG_DSS					2
#define SIG_ALG_ECDSS				3
#define SIG_ALG_ECDSA_256			4
#define SIG_ALG_ECDSA_384			5
#define SIG_ALG_ECDSA_521			6

// GAP Attributes - Type
#define ACTIVATION_TIME_DELAY		1
#define DEACTIVATION_TIME_DELAY		2
#define SENDER_ID_REQUEST			3






typedef struct Key_info{
	char* key;
	int key_size;
	int internal_key_id;
}Key;




typedef struct GroupAssoPolicy_info{
	int activation_time_delay;
	int deactivation_time_delay;
	int sender_id_request;
}GAP;




// NOVAS


// TODO: Change SA KEK Attr and SA TEK Attr to SA KEK Policy and SA TEK Policy 


// KEK Security Associations
typedef struct KEK_SA_Node* KEK_SA_nd;
typedef struct KEKSA_info{	
	uint8_t* spi;
	int spi_size;

	Key key;

	int filled;
}KEK_SA;

// Linked List node
typedef struct KEK_SA_Node {
	KEK_SA kek_sa;
	KEK_SA_nd next;
} ListNode_keksa;


// TEK Security Associations
typedef struct TEK_SA_Node* TEK_SA_nd;
typedef struct TEKSA_info{	
	uint8_t* spi;
	int spi_size;
	
	Key key;

	int filled;
}TEK_SA;

// Linked List node
typedef struct TEK_SA_Node {
	TEK_SA tek_sa;
	TEK_SA_nd next;
} ListNode_teksa;



// Security Associations - should be using kernel key management...
typedef struct Phase1_Node* Phase1_nd;
typedef struct Phase1SA_info{
	int initialized;
	
	uint8_t* icookie;
	uint8_t* rcookie;
	
	Key key;
	
	uint8_t* skeyid_a;
	int skeyid_a_length;
}Phase1SA;

// Linked List node
typedef struct Phase1_Node {
	Phase1SA phase1_sa;
	Phase1_nd next;
} ListNode_phase1;

// Struct to link all Security Associations with Group Member
// Phase1, KEK, TEK, ... 
typedef struct GroupMember_info{
	int initialized;
	KEK_SA_nd kek;
	TEK_SA_nd tek;
}GroupMember;


// SA KEK Policy
typedef struct SAKEK_Policy_Node* KEKPolicy_nd;
typedef struct SAKEK_Policy_info{
	int kek_management_algorithm;
	int kek_algorithm;
	int kek_key_length;
	uint32_t kek_key_lifetime;
	int sig_hash_algorithm;
	int sig_algorithm;
	int sig_key_length;
}KEK_SA_Policy;

// Linked List node
typedef struct SAKEK_Policy_Node {
	KEK_SA_Policy KEK_Policy;
	KEKPolicy_nd next;
} ListNode_sakek_policy;



// SA TEK Policy
typedef struct SATEK_Policy_Node* TEKPolicy_nd;
typedef struct SATEK_Policy_info{
	int protocol_id;
	
	uint8_t oid_length;
	uint16_t oid_payload_length;
	uint32_t spi;
	uint16_t auth_alg;
	uint16_t enc_alg;
	time_t init_key;
	time_t key_lifetime;
	//TODO sa attributes
	
	
}TEK_SA_Policy;

// Linked List node
typedef struct SATEK_Policy_Node {
	TEK_SA_Policy TEK_Policy;
	TEKPolicy_nd next;
} ListNode_satek_policy;





#endif /* sa.h */





