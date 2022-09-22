#include "isakmp.h" 


int validate_isakmphdr_packetlength(char message[MAXLINE], int packet_length){
	if(packet_length < decode_4bytesToInt(message,INDEX_ISAKMP_HDR_LENGTH)){
		// Invalid packet_length
		return -1;
	}else{
		return 0;
	}
}

// TODO 
int validate_isakmp_cookies(char message[MAXLINE], char* icookie, char* rcookie){
	return 0;
}

// Validates ISAKMP Header and returns ExchangeType of message
int validate_isakmp_hdr(char message[MAXLINE], uint8_t majmin, char* icookie, char* rcookie, uint8_t flags, uint32_t m_id){

	uint8_t extype;

	// Initiator and Responder Cookie validation
	int res = validate_isakmp_cookies(message, icookie, rcookie);
	if(res != 0){
		// Error validating cookies
		printf("1\n");
		return -1;
	}
	
	// Validate Major and Minor version
	if(message[INDEX_ISAKMP_HDR_MAJMIN] != majmin){
		// Invalid NextPayload
		printf("2: %d %d\n", message[INDEX_ISAKMP_HDR_MAJMIN], majmin);
		return -1;
	}
	
	// Validate and determine Exchange Type - TODO DELETE 
	// Only implements GDOI related Exchange Type - 32 Pull; 33 - Push
	extype = message[INDEX_ISAKMP_HDR_EXTYPE];
	if(extype != ET_GROUPKEY_PULL && ET_GROUPKEY_PUSH){
		// Invalid exchange type
		printf("3\n");
		return -1;
	}
	
	// Validate NextPayload 
	if(extype == ET_GROUPKEY_PULL){
		// NextPayload MUST be HASH 
		if(message[INDEX_ISAKMP_HDR_NP] != NP_HASH_PAYLOAD){
			// Invalid NextPayload value
			printf("4\n");
			return -1;
		}
	}else if(extype == ET_GROUPKEY_PUSH){
		// NextPayload MUST be SEQ
		if(message[INDEX_ISAKMP_HDR_NP] != NP_SEQUENCENUMBER){
			// Invalid NextPayload value
			printf("5\n");
			return -1;
		}
	}
	
	// Validate Flags
	if(message[INDEX_ISAKMP_HDR_FLAGS] != flags){
		// Invalid flags
		printf("6\n");
		return -1;
	}
	
	// Validate Message ID
	if(decode_4bytesToInt(message, INDEX_ISAKMP_HDR_MID) != m_id){
		// Invalid message id
		printf("7\n");
		return -1;
	}
	
	return extype;
}


