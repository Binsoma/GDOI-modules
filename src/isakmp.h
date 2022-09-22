#ifndef ISAKMP_H__
#define ISAKMP_H__


#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <openssl/sha.h>

#define MAXLINE 1024 

#include "auxf.h"

// INFO
/*
HDR - ISAKMP
	8byte - Initiator Cookie - RFC 2408 - 2.5.3 
	8byte - Responder Cookie - 
	1byte - Next Payload
	4bits - Major Version = 1
	4bits - Minor Verions = 0
	1byte - Exchange Type -> GK-PULL = 32
	1byte - Flags -> Encryption Bit ; Commit bit = 0 ; Authentication Only bit ; Remaining = ZEROS
			- If Enc flag = 1; all payloads following the header are encrypted using ISAKMP SA. 
			- If AuthOnly flag = 1; Payloads are only Authenticated 
	4byte - Message ID
			- Random Value generator by the Initiator of Comms. In Phase 1 MUST be 0. 
	4byte - Length
			- Total length of message (header + all payloads) in bytes
*/


// Header Sizes
#define GENERIC_HDR_SIZE 4
#define ISAKMP_HDR_SIZE 28
#define HDR_COOKIE_SIZE 8

// Indexes
#define INDEX_ISAKMP_HDR_NP			16
#define INDEX_ISAKMP_HDR_MAJMIN		17
#define INDEX_ISAKMP_HDR_EXTYPE		18
#define INDEX_ISAKMP_HDR_FLAGS		19 
#define INDEX_ISAKMP_HDR_MID		20 
#define INDEX_ISAKMP_HDR_LENGTH		24

// Next Payload defines
#define NP_LASTPAYLOAD		0
#define NP_SA		 		1
#define NP_IDENTIFICATION 	5
#define NP_HASH_PAYLOAD 	8
#define NP_SIGNATURE 		9
#define NP_NONCE	 		10
#define NP_DELETE	 		12
#define NP_SAKEK	 		15
#define NP_SATEK	 		16
#define NP_KEYDOWNLOAD 		17
#define NP_SEQUENCENUMBER 	18
#define NP_GAP		 		22

// Exchange Type defines 
#define ET_GROUPKEY_PULL	32
#define ET_GROUPKEY_PUSH	33

// DOI
#define DOI_GDOI			2


// HASH Algorithm defines
#define HASH_NONE			0
#define HASH_SHA256 		1

// Nonce Defines
#define NONCE_LENGTH 8

// Key Download Types
#define KD_TEK	1
#define KD_KEK	2


#endif /* isakmp.h */
