#include "gdoi.h"

/* GDOI PAYLOADS */
int gdoi_createPayloadIsakmp_HDR(uint8_t* icookie, uint8_t* rcookie, uint8_t next_payload, uint8_t versions, uint8_t extype, uint8_t flags, uint32_t m_id, uint32_t length, uint8_t** dest, int debug){
	/* 
		Returns length (in bytes) of created payload 
		dest holds created payload
	*/
	
	int total_length = 28; 										// Length (in bytes) of HDR 
	int index;
	
	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}
	
	index = 0;
	
	memcpy(*dest, icookie, HDR_COOKIE_SIZE);					// Initiator Cookie
	index += 8;
	
	memcpy(&(*dest)[index], rcookie, HDR_COOKIE_SIZE);			// Responder Cookie
	index += 8;
	
	(*dest)[index] = next_payload;								// Next Payload
	index++;
	
	(*dest)[index] = versions;									// Major and Minor Version
	index++;
	
	(*dest)[index] = extype;									// Exchange Type
	index++;
	
	(*dest)[index] = flags;										// Flags
	index++;
	
	encodeInt4Bytes(*dest, m_id, index);						// Message ID
	index += 4;
	
	encodeInt4Bytes(*dest, length, index);						// Length
	index += 4;
	
	//printf("HDR = %d\n", index);
	return index;
}

int gdoi_createPayloadHash(uint8_t next_payload, uint16_t payload_length, uint8_t* hash_data, uint8_t** dest, int debug){
	
	int total_length = GENERIC_HDR_SIZE+payload_length; 		// Length (in bytes) of HDR 
	int index;
	
	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}
	
	index = 0;
	
	(*dest)[index] = next_payload;								// Next Payload
	index++;
	
	(*dest)[index] = 0;											// Reserved Byte
	index++;
	
	encodeInt2Bytes(*dest, payload_length, index);				// Hash data Length
	index += 2;
	
	memcpy(&(*dest)[index], hash_data, payload_length-index);	// Hash data
	index += payload_length-index;
	
	//printf("HASH = %d\n", index);
	return index;
}

int gdoi_createPayloadNonce(uint8_t next_payload, uint16_t payload_length, uint8_t* nonce_data, uint8_t** dest, int debug){
	
	int total_length = GENERIC_HDR_SIZE+payload_length; 		// Length (in bytes) of HDR 
	int index;
	
	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}
	
	index = 0;
	
	(*dest)[index] = next_payload;								// Next Payload
	index++;
	
	(*dest)[index] = 0;											// Reserved Byte
	index++;
	
	encodeInt2Bytes(*dest, payload_length, index);				// Nonce data Length
	index += 2;
	
	memcpy(&(*dest)[index], nonce_data, payload_length-index);					// Nonce data
	index += payload_length-index;
	
	return index;

}

int gdoi_createPayloadId(uint8_t next_payload, uint16_t payload_length, uint8_t id_type, uint8_t* id_data_payload, uint8_t** dest, int debug){

	int total_length = GENERIC_HDR_SIZE+payload_length; 		// Length (in bytes) of HDR 
	int index;
	
	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}
	
	index = 0;
	
	(*dest)[index] = next_payload;								// Next Payload
	index++;
	
	(*dest)[index] = 0;											// Reserved Byte
	index++;
	
	encodeInt2Bytes(*dest, payload_length, index);				// ID data Length
	index += 2;
	
	(*dest)[index] = id_type;									// ID Type
	index++;
	
	memset(&(*dest)[index], 0, 3);								// DOI Specific ID data
	index += 3;
	
	memcpy(&(*dest)[index], id_data_payload, payload_length-index);	// ID data
	index += payload_length-index;
	
	//printf("ID = %d\n", index);
	return index;
}


// TO SEE
int gdoi_createPayloadSA(uint8_t next_payload, uint32_t doi, uint32_t situation, uint16_t sa_attribute_next_p, uint8_t* sa_attributes, int sa_attributes_length,uint8_t** dest, int debug){
	
	int payload_length = 12;
	int total_length = GENERIC_HDR_SIZE+payload_length+sa_attributes_length; 		// Length (in bytes) of HDR 
	int index;
	
	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}
	
	index = 0;
	
	(*dest)[index] = next_payload;								// Next Payload
	index++;
	
	(*dest)[index] = 0;											// Reserved Byte
	index++;
	
	encodeInt2Bytes(*dest, total_length, index);				// SA payload Length
	index += 2;
		
	encodeInt4Bytes(*dest, doi, index);							// DOI
	index += 4;
	
	encodeInt4Bytes(*dest, situation, index);					// Situation
	index += 4;	
	
	encodeInt2Bytes(*dest, sa_attribute_next_p, index);			// SA Attribute Next Payload
	index += 2;
	
	encodeInt2Bytes(*dest, 0, index);							// Reserved2
	index += 2;
	
	// TODO ADD SA_ATTRIBUTES
	memcpy(&(*dest)[index], sa_attributes, sa_attributes_length);
	index += sa_attributes_length;
	
	//printf("SA = %d\n", index);
	return index;
}

int gdoi_createSAKEK_Payload(int gk_protocol, uint8_t next_payload, uint8_t protocol, uint8_t src_id_type, uint16_t src_id_port, uint8_t src_id_len, uint8_t* src_id_data, uint8_t dst_id_type, uint16_t dst_id_port, uint8_t dst_id_len, uint8_t* dst_id_data, uint8_t* spi, KEKPolicy_nd sa_kek, GroupMember* GM_SAs ,uint8_t** dest, int debug){
	// TODO
	// Create the SAK (SA KEK) Sub payload for SA Payload. Takes the KEK Policy defined by GCKS and creates the payload based on the attributes defined. 
	// Transverse the KEK Policy and for the attributes that exist creates the payload entry following a Type/Value or Type/Length/Value form. 
	
	// Fixed size values + already know sizes - missing attributes TV/TLV size
	int total_length = 33 + src_id_len + dst_id_len; 
	int index;
	
	
	// Get Attributes size from KEK Policy - KEK_ALGORITHM and SIG_ALGORITHM are MANDATORY. Other are optional.
	uint8_t* kek_management_algorithm = NULL;
	uint8_t* kek_algorithm = NULL;
	uint8_t* kek_key_length = NULL;
	uint8_t* kek_key_lifetime = NULL;
	uint8_t* sig_hash_algorithm = NULL;
	uint8_t* sig_algorithm = NULL;
	uint8_t* sig_key_length = NULL;
	
		
	// If we are on GK-PULL, KEK_MANAGEMENT_ALGORITHM must not be sent (RFC 6407, page 23). Otherwise, is included
	if(gk_protocol == GK_PUSH){
		if(sa_kek->KEK_Policy.kek_management_algorithm != -1){
			// Attribute exists - BASIC - TV
			// Type = 1
			kek_management_algorithm = (uint8_t*)malloc(sizeof(char)*TV_LENGTH);
			if(kek_management_algorithm == NULL){
				perror("Memory exausted");
				return -1;
			}

			uint16_t val = 1;
			val = modify2Byte(val, 15, 1);
			encodeInt2Bytes(kek_management_algorithm, val, 0);
			
			// Set value
			encodeInt2Bytes(kek_management_algorithm, sa_kek->KEK_Policy.kek_management_algorithm, 2);
			
			// Update total_length
			total_length += TV_LENGTH;
		}
	}
		
	if(sa_kek->KEK_Policy.kek_algorithm != -1){		// MANDATORY
		// Attribute exists - BASIC - TV
		// Type = 2
		kek_algorithm = (uint8_t*)malloc(sizeof(char)*TV_LENGTH);
		if(kek_algorithm == NULL){
			perror("Memory exausted");
			return -1;
		}
				
		uint16_t val = 2;
		val = modify2Byte(val, 15, 1);
		encodeInt2Bytes(kek_algorithm, val, 0);
		
		// Set value
		encodeInt2Bytes(kek_algorithm, sa_kek->KEK_Policy.kek_algorithm, 2);
		
		// Update total_length
		total_length += TV_LENGTH;
	}else{
		// Error - should be present
		perror("kek_algorithm must be defined in KEK Policy");
		return -1;
	}
		
	if(sa_kek->KEK_Policy.kek_key_length != -1){
		// Attribute exists - BASIC - TV
		// Type = 3
		kek_key_length = (uint8_t*)malloc(sizeof(char)*TV_LENGTH);
		if(kek_key_length == NULL){
			perror("Memory exausted");
			return -1;
		}

		uint16_t val = 3;
		val = modify2Byte(val, 15, 1);
		encodeInt2Bytes(kek_key_length, val, 0);
		
		// Set value
		encodeInt2Bytes(kek_key_length, sa_kek->KEK_Policy.kek_key_length, 2);
		
		// Update total_length
		total_length += TV_LENGTH;
	}
		
	if(sa_kek->KEK_Policy.kek_key_lifetime != -1){
		// Attribute exists - VARIABLE - TLV - 4 bytes
		// Type = 4
		kek_key_lifetime = (uint8_t*)malloc(sizeof(char)*TV_LENGTH+4);
		if(kek_key_lifetime == NULL){
			perror("Memory exausted");
			return -1;
		}
		encodeInt2Bytes(kek_key_lifetime, 4, 0);
		// TODO: Verify AF bit is 0 
		//kek_key_length |= 1 << 0;		// AF Bit -> 1 means the Attribute is TV
		
		// Set Length
		encodeInt2Bytes(kek_key_lifetime, 4, 2);
		
		// Set Value
		encodeInt4Bytes(kek_key_lifetime, sa_kek->KEK_Policy.kek_key_lifetime, 4);	

		// Update total_length
		total_length += TV_LENGTH + 4;
	}
		
	if(sa_kek->KEK_Policy.sig_hash_algorithm != -1){
		// Attribute exists - BASIC - TV
		// Type = 5
		sig_hash_algorithm = (uint8_t*)malloc(sizeof(char)*TV_LENGTH);
		if(sig_hash_algorithm == NULL){
			perror("Memory exausted");
			return -1;
		}
		uint16_t val = 5;
		val = modify2Byte(val, 15, 1);
		encodeInt2Bytes(sig_hash_algorithm, val, 0);
		
		// Set value
		encodeInt2Bytes(sig_hash_algorithm, sa_kek->KEK_Policy.sig_hash_algorithm, 2);
		
		// Update total_length
		total_length += TV_LENGTH;
	}
		
	if(sa_kek->KEK_Policy.sig_algorithm != -1){
		// Attribute exists - BASIC - TV
		// Type = 6
		sig_algorithm = (uint8_t*)malloc(sizeof(char)*TV_LENGTH);
		if(sig_algorithm == NULL){
			perror("Memory exausted");
			return -1;
		}
		uint16_t val = 6;
		val = modify2Byte(val, 15, 1);
		encodeInt2Bytes(sig_algorithm, val, 0);


		// Set value
		encodeInt2Bytes(sig_algorithm, sa_kek->KEK_Policy.sig_algorithm, 2);
		
		// Update total_length
		total_length += TV_LENGTH;
	}
		
	if(sa_kek->KEK_Policy.sig_key_length != -1){
		// Attribute exists - BASIC - TV
		// Type = 7
		sig_key_length = (uint8_t*)malloc(sizeof(char)*TV_LENGTH);
		if(sig_key_length == NULL){
			perror("Memory exausted");
			return -1;
		}
		uint16_t val = 7;
		val = modify2Byte(val, 15, 1);
		encodeInt2Bytes(sig_key_length, val, 0);
		
		// Set value
		encodeInt2Bytes(sig_key_length, sa_kek->KEK_Policy.sig_key_length, 2);
		
		// Update total_length
		total_length += TV_LENGTH;
	}
		
	// Create SAK Payload (SA KEK)
	
	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}

	index = 0;
	(*dest)[index] = next_payload;					// Next Payload
	index++;
	
	(*dest)[index] = 0x00;							// Reserved
	index++;
	
	encodeInt2Bytes(*dest, total_length, index);	// Payload Length
	index += 2;
	
	(*dest)[index] = protocol;						// Protocol
	index++;
	
	(*dest)[index] = src_id_type;					// SRC ID Type
	index++;
	
	encodeInt2Bytes(*dest, src_id_port, index);		// SRC ID Port
	index += 2;
	
	(*dest)[index] = src_id_len;					// SRC ID Length
	index++;
	
	memcpy(&(*dest)[index], src_id_data, src_id_len);	// SRC ID Data
	index += src_id_len;
	
	(*dest)[index] = dst_id_type;					// DST ID Type
	index++;
	
	encodeInt2Bytes(*dest, dst_id_port, index);		// DST ID Port
	index += 2;
	
	(*dest)[index] = dst_id_len;					// DST ID Length
	index++;
	
	memcpy(&(*dest)[index], dst_id_data, dst_id_len);	// DST ID Data
	index += dst_id_len;
	
	memcpy(&(*dest)[index], spi, 16);				// SPI
	index += 16;

	encodeInt4Bytes(*dest, 0, index);				// RESERVED
	index += 4;


	// TODO: Support multiple KEKs
	// Create and fill GroupMember KEK Sec Assoc, from policy
	// Allocate memory or KEK Structure
	if((*GM_SAs).kek == NULL){
		// First time
		(*GM_SAs).kek = (KEK_SA_nd)malloc(sizeof(ListNode_keksa));
	}else{
		free((*GM_SAs).kek);
		(*GM_SAs).kek = (KEK_SA_nd)malloc(sizeof(ListNode_keksa));
	}

	// Allocate memory for the spi
	(*GM_SAs).kek->kek_sa.spi = (uint8_t*)malloc(sizeof(char)*16);
	(*GM_SAs).kek->kek_sa.spi_size = 16;

	// Copy SPI
	memcpy((*GM_SAs).kek->kek_sa.spi, spi, 16);


	// Append attrubutes 
	if(kek_management_algorithm != NULL){
		memcpy(&(*dest)[index], kek_management_algorithm, TV_LENGTH);
		index += TV_LENGTH;
		free(kek_management_algorithm);
	}
	
	if(kek_algorithm != NULL){
		memcpy(&(*dest)[index], kek_algorithm, TV_LENGTH);
		index += TV_LENGTH;
		free(kek_algorithm);
	}
	
	if(kek_key_length != NULL){
		memcpy(&(*dest)[index], kek_key_length, TV_LENGTH);
		index += TV_LENGTH;
		free(kek_key_length);
	}
	
	if(kek_key_lifetime != NULL){
		memcpy(&(*dest)[index], kek_key_lifetime, TV_LENGTH+4);
		index += (TV_LENGTH+4);
		free(kek_key_lifetime);
	}
	
	if(sig_hash_algorithm != NULL){
		memcpy(&(*dest)[index], sig_hash_algorithm, TV_LENGTH);
		index += TV_LENGTH;
		free(sig_hash_algorithm);
	}
	
	if(sig_algorithm != NULL){
		memcpy(&(*dest)[index], sig_algorithm, TV_LENGTH);
		index += TV_LENGTH;
		free(sig_algorithm);
	}
	
	if(sig_key_length != NULL){
		memcpy(&(*dest)[index], sig_key_length, TV_LENGTH);
		index += TV_LENGTH;
		free(sig_key_length);
	}
	
	return index;
	
}

int gdoi_createSATEK_Payload(int protocol_id, uint8_t oid_length, uint8_t* oid, uint16_t oid_specific_payload_length, uint8_t* oid_specific_payload, uint32_t spi, uint16_t auth_alg, uint16_t enc_alg, uint32_t remain_lifetime, int sa_data_attributes_length, uint8_t* sa_data_attributes, uint8_t** dest, int debug){
	
}

int gdoi_createKD_Payload(uint8_t next_payload, int number_of_keys, uint8_t* key_packets, int key_packets_size, uint8_t** dest){
	
	// Calculate total length of payload
	int total_length = 64 + key_packets_size;
	int index;
	
	// Allocate memory
	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}

	// Copy data
	index = 0;
	
	(*dest)[index] = next_payload;								// Next Payload
	index++;

	(*dest)[index] = 0;											// Reserved Byte
	index++;
	
	encodeInt2Bytes(*dest, total_length, index);				// Payload Length
	index += 2;
	
	encodeInt2Bytes(*dest, number_of_keys, index);				// Number of key packets
	index += 2;
	
	encodeInt2Bytes(*dest, 0, index);							// Number of key packets
	index += 2;
	
	memcpy(&(*dest)[index], key_packets, key_packets_size);		// Copy KeyPackets
	index += key_packets_size;
	
	return index;
}



int gdoi_createKeyPacket_TEK(int kd_type, int spi_size, uint8_t* spi, int key_data_size, uint8_t* key_data, int salt_data_size, uint8_t* salt_data, uint8_t** dest, int debug){

	int total_length = 40 + spi_size + key_data_size + salt_data_size; 		// Length (in bytes) of keypacket  
	int index;

	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}

	index = 0;
	(*dest)[index] = kd_type;					// KD Type
	index++;

	(*dest)[index] = 0;							// RESERVED
	index++;

	encodeInt2Bytes(*dest, total_length, index);	// KD Length
	index += 2;

	(*dest)[index] = spi_size;					// SPI Size
	index++;
	
	memcpy(&(*dest)[index], spi, spi_size);		// SPI 
	index += spi_size;
	
	// Copy Key data + additional data (IV if exists)
	if(salt_data_size > 0){
		memcpy(&(*dest)[index], salt_data, salt_data_size);		// SPI 
		index += salt_data_size;
	}
	
	memcpy(&(*dest)[index], key_data, key_data_size);		// SPI 
	index += key_data_size;
	
	return index;

}


int gdoi_createKeyPacket_KEK(int kd_type, int spi_size, uint8_t* spi, int key_data_size, uint8_t* key_data, int iv_data_size, uint8_t* iv_data, uint8_t** dest, int debug){
	
	int total_length = 40 + spi_size + key_data_size + iv_data_size; 		// Length (in bytes) of keypacket  
	int index;

	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}

	index = 0; 
	(*dest)[index] = kd_type;					// KD Type
	index++;

	(*dest)[index] = 0;							// RESERVED
	index++;

	encodeInt2Bytes(*dest, total_length, index);	// KD Length
	index += 2;
	
	printf("Aquiiiiii\n");

	(*dest)[index] = spi_size;					// SPI Size
	index++;
	
	printf("Aquiiiiii22222\n");
	
	memcpy(&(*dest)[index], spi, spi_size);		// SPI 
	index += spi_size;
	
	printf("Aquiiiiii22222333333\n");
	
	// Copy Key data + additional data (IV if exists)
	if(iv_data_size > 0){
		memcpy(&(*dest)[index], iv_data, iv_data_size);		// SPI 
		index += iv_data_size;
	}
	
	memcpy(&(*dest)[index], key_data, key_data_size);		// SPI 
	index += key_data_size;
	
	return index;
	

}


// R-GOOSE Specific GDOI Payload
int rgoose_createPayloadIdData(uint8_t oid_length, uint8_t* oid, uint16_t oid_specific_payload_length, uint8_t* oid_specific_payload, uint8_t** dest, int debug){
	
	int total_length = 3+oid_length+oid_specific_payload_length; // Length (in bytes) of HDR 
	int index;
	
	*dest = (uint8_t*)malloc(sizeof(char)*total_length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}
	
	index = 0;
	
	(*dest)[index] = oid_length;								// OID Length
	index++;
	
	memcpy(&(*dest)[index], oid, oid_length);					// OID
	index += oid_length;
	
	encodeInt2Bytes(*dest, oid_specific_payload_length, index);	// OID Specific Payload Length
	index += 2;
	
	// 0-Length verification
	if(oid_specific_payload_length > 0){
		memcpy(&(*dest)[index], oid_specific_payload, oid_specific_payload_length);	// OID Specific Payload
		index += oid_specific_payload_length;
	}
	
	return index;
}


// Create GDOI - GroupKey-Pull 
int gdoi_create_groupkeypull_m1(uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* oid, int oid_length, int id_type, uint8_t** message, uint8_t** dest_ni, int* dest_ni_length, int debug){
	//printf("---------- Message 1 ----------\n");
		
	int index, ni_length, id_payload_length, hash_payload_length;
	int concat_data_length = skeyid_a_length+sizeof(m_id);
	
	// Create Ni data
	uint8_t* nonce_data = NULL;
	int res = crypto_generateNonceByteStream(NONCE_LENGTH, &nonce_data);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 1 -> Nonce Generation");
		return -1;
	}


	if(dest_ni != NULL && dest_ni_length != NULL){
		
		*dest_ni_length = res;
		*dest_ni = (uint8_t*)malloc(sizeof(char)*res);
		if(*dest_ni == NULL){
			perror("Memory exausted");
			return -1;
		}

		memcpy(*dest_ni, nonce_data, res);
	}
	
	if(debug){
		printf("Nonce Data Length: %d\n", res);
		printf("Nonce Data: "); printPayload(nonce_data, res);
		printf("\n\n");
	}

	// Create Ni Payload
	uint8_t* ni = NULL;
	res = gdoi_createPayloadNonce(NP_IDENTIFICATION, GENERIC_HDR_SIZE+NONCE_LENGTH, nonce_data, &ni, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 1 -> Nonce Payload Creation");
		return -1;
	}
	
	if(debug){	
		printf("Ni Payload Length: %d\n", res);
		printf("Ni Payload: "); printPayload(ni, res);
		printf("\n\n");
	}
	
	// Update concat_data_length with Ni size
	ni_length = res;
	concat_data_length += ni_length;

	// Create ID data
	uint8_t* id_data = NULL;
	res = rgoose_createPayloadIdData(oid_length, oid, 0, NULL, &id_data, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 1 -> ID Data (OID-based)");
		return -1;
	}
	
	
	if(debug){	
		printf("ID Data Length: %d\n", res);
		printf("ID Data: "); printPayload(id_data, res);
		printf("\n\n");
	}
		
	// Create ID Payload
	uint8_t* id_payload = NULL;
	res = gdoi_createPayloadId(NP_LASTPAYLOAD, GENERIC_HDR_SIZE+4+res, id_type, id_data, &id_payload, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 1 -> Identification Payload");
		return -1;
	}

	if(debug){	
		printf("ID Payload Length: %d\n", res);
		printf("ID Payload Data: "); printPayload(id_payload, res);
		printf("\n\n");
	}

	
	// Update concat_data_length with ID payload size
	id_payload_length = res;
	concat_data_length += id_payload_length;
	
	// Create Hash data
	uint8_t* concat_data = NULL;
	concat_data = (uint8_t*)malloc(sizeof(char)*concat_data_length);
	
	// Concat data -> SKEYID_a, M-ID | Ni | ID
	memcpy(concat_data, skeyid_a, skeyid_a_length);
	encodeInt4Bytes(concat_data, m_id, sizeof(m_id));
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)], ni, ni_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)+ni_length], id_payload, id_payload_length);
	
	if(debug){	
		printf("Concat Size = %d\n", concat_data_length);
		printf("Concat Data: "); printPayload(concat_data, concat_data_length);
		printf("\n\n");
	}
		
	// Calculate Hash Data
	uint8_t* hash_data = NULL;
	
	// prf(SKEYID_a, M-ID | Ni | ID)
	res = crypto_calculateHash(HASH_SHA256, concat_data_length, concat_data, &hash_data);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 1 -> CalculateHash");
		return -1;
	}
	
		
	int hash_data_length = res;
	
	if(debug){		
		printf("Hash Length: %d\n", SHA256_DIGEST_LENGTH);
		printf("Hash Data: "); printPayload(hash_data, SHA256_DIGEST_LENGTH);
		printf("\n\n");
	}

		
	// Create Hash Paylaod
	uint8_t* hash_payload = NULL;
	res = gdoi_createPayloadHash(NP_NONCE, GENERIC_HDR_SIZE+hash_data_length, hash_data, &hash_payload, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 1 -> HashPayload");
		return -1;
	}
	hash_payload_length = res;
	
	if(debug){	
		printf("Hash Payload Length: %d\n", res);
		printf("Hash Payload: "); printPayload(hash_payload, res);
		printf("\n\n");
	}
	
	// Finally, construct HDR
	int hdr_length = ISAKMP_HDR_SIZE+hash_payload_length+ni_length+id_payload_length;
	uint8_t* hdr = NULL;
	res = gdoi_createPayloadIsakmp_HDR(icookie, rcookie, NP_HASH_PAYLOAD, 0x10, ET_GROUPKEY_PULL, 0, m_id, hdr_length, &hdr, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 1 -> HDR ISAKMP");
		return -1;
	}
	
	if(debug){	
		printf("HDR ISAKMP Length: %d\n", res);
		printf("HDR ISAKMP Payload: "); printPayload(hdr, res);
		printf("\n\n");
	}
	
	
	// Create full message
	*message = (uint8_t*)malloc(sizeof(char)*hdr_length);
	
	memcpy(*message, hdr, ISAKMP_HDR_SIZE);
	memcpy(&(*message)[ISAKMP_HDR_SIZE], hash_payload, hash_payload_length);
	memcpy(&(*message)[ISAKMP_HDR_SIZE+hash_payload_length], ni, ni_length);
	memcpy(&(*message)[ISAKMP_HDR_SIZE+hash_payload_length+ni_length], id_payload, id_payload_length);
	
	if(debug){	
		printf("Full Message Length: %d\n", hdr_length);
		printf("Full Message: "); printPayload(*message, hdr_length);
		printf("\n\n");
	}
	
	// Free Memory
	free(nonce_data);
	free(ni);
	free(id_data);
	free(id_payload);
	free(concat_data);
	free(hash_data);
	free(hash_payload);
	free(hdr);
	
	return hdr_length;	
}

int gdoi_create_groupkeypull_m2(uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* ni, int ni_length, uint32_t doi, uint32_t situation, uint16_t sa_attribute_next_p, KEKPolicy_nd sa_kek, TEKPolicy_nd sa_tek, GroupMember* GM_SAs, uint8_t** message, uint8_t** nr, int* nr_length, int debug){
	int index;
	int nr_payload_length;
	int sa_payload_length;
	int concat_data_length = skeyid_a_length+sizeof(m_id)+ni_length;

	// Create Nr data
	uint8_t* nonce_data = NULL;
	int res = crypto_generateNonceByteStream(NONCE_LENGTH, &nonce_data);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 2 -> Nonce Generation");
		return -1;
	}

	*nr_length = res;
	*nr = (uint8_t*)malloc(sizeof(char)*(*nr_length));
	memcpy(*nr, nonce_data, res);
	
	// Create Nr Payload
	uint8_t* nr_payload = NULL;
	nr_payload_length = gdoi_createPayloadNonce(NP_SA, GENERIC_HDR_SIZE+NONCE_LENGTH, nonce_data, &nr_payload, debug);
	if(nr_payload_length == -1){
		perror("System Error - GroupKey-Pull -> Message 2 -> Nonce Payload Creation");
		return -1;
	}
	
	concat_data_length += nr_payload_length;


	// SA Attributes (SAKEK + SATEK (+ SATEK...))
	uint8_t* sa_attributes = NULL;
	int sa_attributes_length = 0;

	//SA KEK
	uint8_t* sakek_payload = NULL;
	int sakek_payload_length = 0;


	// SA Creation --- TODO CHANGE
	/* Generate new SA :TODO:*/
	uint8_t* spi = (uint8_t*)malloc(sizeof(char)*16);
	memcpy(spi, icookie, 8);
	memcpy(&spi[8], rcookie, 8);
	
	uint8_t protocol = 17;
	
	uint8_t src_id_type = 0x01;
	uint16_t src_id_port = 4; // TO CHANGE - Use client_nd struct
	uint8_t src_id_len = strlen("127.0.0.1");
	uint8_t* src_id_data = (uint8_t*)malloc(sizeof(char)*strlen("127.0.0.1"));
	
	memcpy(src_id_data, "127.0.0.1", strlen("127.0.0.1")); // TO CHANGE 
		
	uint8_t dst_id_type = 0x01;
	uint16_t dst_id_port = 4;
	uint8_t dst_id_len = strlen("127.0.0.1");
	uint8_t* dst_id_data = (uint8_t*)malloc(sizeof(char)*strlen("127.0.0.1"));
	memcpy(dst_id_data, "127.0.0.1", strlen("127.0.0.1")); // TO CHANGE 


	sakek_payload_length = gdoi_createSAKEK_Payload(GK_PULL, NP_LASTPAYLOAD, protocol, src_id_type, src_id_port, src_id_len, src_id_data, dst_id_type, dst_id_port, dst_id_len, dst_id_data, spi, sa_kek, GM_SAs, &sakek_payload, debug);
	if(sakek_payload_length == -1){
		perror("System Error - GroupKey-Pull -> Message 2 -> SA KEK Payload creation");
		return -1;
	}

	sa_attributes_length += sakek_payload_length;


	// SA TEK Payload


	sa_attributes = (uint8_t*)malloc(sizeof(char)*sa_attributes_length);
	memcpy(sa_attributes, sakek_payload, sakek_payload_length);


	// SA Payload
	uint8_t* sa_payload = NULL;
	sa_payload_length = gdoi_createPayloadSA(NP_LASTPAYLOAD, doi, situation, sa_attribute_next_p, sa_attributes, sa_attributes_length, &sa_payload, debug);
	if(sa_payload_length == -1){
		perror("System Error - GroupKey-Pull -> Message 2 -> SA Payload");
		return -1;
	}

	concat_data_length += sa_payload_length;

	// Create Concat data
	uint8_t* concat_data = NULL;
	concat_data = (uint8_t*)malloc(sizeof(char)*concat_data_length);

	memcpy(concat_data, skeyid_a, skeyid_a_length);							
	encodeInt4Bytes(concat_data, m_id, skeyid_a_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)], ni, ni_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)+ni_length], nr_payload, nr_payload_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)+ni_length+nr_payload_length], sa_payload, sa_payload_length);

	// Calculate Hash
	uint8_t* hash_data = NULL;
	int hash_data_length = 0;
	hash_data_length = crypto_calculateHash(HASH_SHA256, concat_data_length, concat_data, &hash_data);
	if(hash_data_length == -1){
		perror("System Error - GroupKey-Pull -> Message 2 -> CalculateHash");
		return -1;
	}

	// Create Hash Payload
	uint8_t* hash_payload = NULL;
	int hash_payload_length = 0;
	hash_payload_length = gdoi_createPayloadHash(NP_NONCE, GENERIC_HDR_SIZE+hash_data_length, hash_data, &hash_payload, debug);
	if(hash_payload_length == -1){
		perror("System Error - GroupKey-Pull -> Message 2 -> HashPayload");
		return -1;
	}


	// Create ISAKMP HDR
	uint8_t* hdr = NULL;
	int hdr_length = ISAKMP_HDR_SIZE+hash_payload_length+nr_payload_length+sa_payload_length;
	res = gdoi_createPayloadIsakmp_HDR(icookie, rcookie, NP_HASH_PAYLOAD, 0x10, ET_GROUPKEY_PULL, 0, m_id, hdr_length, &hdr, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 2 -> HDR ISAKMP");
		return -1;
	}

	*message = (uint8_t*)malloc(sizeof(char)*hdr_length);
	memcpy(*message, hdr, ISAKMP_HDR_SIZE);
	memcpy(&(*message)[ISAKMP_HDR_SIZE], hash_payload, hash_payload_length);
	memcpy(&(*message)[ISAKMP_HDR_SIZE+hash_payload_length], nr_payload, nr_payload_length);
	memcpy(&(*message)[ISAKMP_HDR_SIZE+hash_payload_length+nr_payload_length], sa_payload, sa_payload_length);

	// Free Memory
	free(nonce_data);
	free(nr_payload);
	free(sa_attributes);
	free(sakek_payload);
	free(src_id_data);
	free(dst_id_data);
	free(sa_payload);
	free(concat_data);
	free(hash_data);
	free(hash_payload);
	free(hdr);

	return hdr_length;
	
}

int gdoi_create_groupkeypull_m3(uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* ni, int ni_length, uint8_t* nr, int nr_length, uint8_t** message, int debug){
	
	int res, hash_payload_length;
	int concat_data_length = skeyid_a_length + sizeof(m_id) + ni_length + nr_length; 
	
	// Create Hash data
	uint8_t* concat_data = NULL;
	concat_data = (uint8_t*)malloc(sizeof(char)*concat_data_length);
	
	// Concat data -> SKEYID_a, M-ID | Ni | Nr
	memcpy(concat_data, 											skeyid_a, 			skeyid_a_length);
	encodeInt4Bytes(concat_data, m_id, skeyid_a_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)], 				ni, 				ni_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)+ni_length],	nr, 				nr_length);

	// Calculate Hash Data
	uint8_t* hash_data = NULL;
	
	// prf(SKEYID_a, M-ID | Ni | ID)
	res = crypto_calculateHash(HASH_SHA256, concat_data_length, concat_data, &hash_data);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 3 -> CalculateHash");
		return -1;
	}
	
	int hash_data_length = res;
	
	// Create Hash Paylaod
	uint8_t* hash_payload = NULL;
	res = gdoi_createPayloadHash(NP_LASTPAYLOAD, GENERIC_HDR_SIZE+hash_data_length, hash_data, &hash_payload, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 3 -> HashPayload");
		return -1;
	}
	hash_payload_length = res;

	
	// Create ISAKMP HDR
	uint8_t* hdr = NULL;
	int hdr_length = ISAKMP_HDR_SIZE+hash_payload_length;
	res = gdoi_createPayloadIsakmp_HDR(icookie, rcookie, NP_HASH_PAYLOAD, 0x10, ET_GROUPKEY_PULL, 0, m_id, hdr_length, &hdr, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 3 -> HDR ISAKMP");
		return -1;
	}

	*message = (uint8_t*)malloc(sizeof(char)*hdr_length);
	memcpy(*message, hdr, ISAKMP_HDR_SIZE);
	memcpy(&(*message)[ISAKMP_HDR_SIZE], hash_payload, hash_payload_length);

	free(concat_data);
	free(hash_data);
	free(hash_payload);
	free(hdr);

	return hdr_length;
	
}

int gdoi_create_groupkeypull_m4(uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* ni, int ni_length, uint8_t* nr, int nr_length, uint8_t* seq_payload, int seq_length, uint8_t* kd_payload, int kd_length, uint8_t** message, int debug){
	
	// HDR*, HASH(4), [SEQ,] KD
	
	// HASH(4) - prf(SKEYID_a, M-ID | Ni_b | Nr_b | KD)
	
	int res, hash_payload_length;
	int concat_data_length = skeyid_a_length + sizeof(m_id) + ni_length + nr_length + seq_length + kd_length; 
	
	// Create Hash data
	uint8_t* concat_data = NULL;
	concat_data = (uint8_t*)malloc(sizeof(char)*concat_data_length);
	
	// Concat data -> SKEYID_a, M-ID | Ni | Nr | KD
	memcpy(concat_data, 											skeyid_a, 			skeyid_a_length);
	encodeInt4Bytes(concat_data, m_id, skeyid_a_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)], 				ni, 				ni_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)+ni_length],	nr, 				nr_length);
	memcpy(&concat_data[skeyid_a_length+sizeof(m_id)+ni_length+nr_length],	kd_payload, kd_length);

	// Calculate Hash Data
	uint8_t* hash_data = NULL;
	
	// prf(SKEYID_a, M-ID | Ni | ID)
	res = crypto_calculateHash(HASH_SHA256, concat_data_length, concat_data, &hash_data);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 4 -> CalculateHash");
		return -1;
	}
	
	int hash_data_length = res;
	
	// Create Hash Paylaod
	uint8_t* hash_payload = NULL;
	res = gdoi_createPayloadHash(NP_KEYDOWNLOAD, GENERIC_HDR_SIZE+hash_data_length, hash_data, &hash_payload, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 4 -> HashPayload");
		return -1;
	}
	hash_payload_length = res;
	
	// Create ISAKMP HDR
	uint8_t* hdr = NULL;
	int hdr_length = ISAKMP_HDR_SIZE+hash_payload_length+seq_length+kd_length;
	res = gdoi_createPayloadIsakmp_HDR(icookie, rcookie, NP_HASH_PAYLOAD, 0x10, ET_GROUPKEY_PULL, 0, m_id, hdr_length, &hdr, debug);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Message 3 -> HDR ISAKMP");
		return -1;
	}

	*message = (uint8_t*)malloc(sizeof(char)*hdr_length);
	memcpy(*message, hdr, ISAKMP_HDR_SIZE);
	memcpy(&(*message)[ISAKMP_HDR_SIZE], hash_payload, hash_payload_length);
	memcpy(&(*message)[ISAKMP_HDR_SIZE+hash_payload_length], kd_payload, kd_length);
	
	free(concat_data);
	free(hash_data);
	free(hash_payload);
	free(hdr);
	
	return hdr_length;
}



int gdoi_process_groupkeypull_m1(uint8_t* message, uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t** ni, int* ni_length, uint8_t** group_id, int* group_id_length){
	int index = 0;
	
	// Validate HASH(1) - "+2" -> Length of each payload, in Generic Header
	int hash_length = decode_2bytesToInt(message, ISAKMP_HDR_SIZE+2);
	*ni_length = decode_2bytesToInt(message, ISAKMP_HDR_SIZE+hash_length+2);
	int id_payload_length = decode_2bytesToInt(message, ISAKMP_HDR_SIZE+hash_length+(*ni_length)+2);
	int to_hash_length = skeyid_a_length + sizeof(m_id) + (*ni_length) + id_payload_length;
	
	
	// TODO: MUDAR HASH_SHA256 PARA A CONF DA SA EM USO
	uint8_t* to_hash = (uint8_t*)malloc(sizeof(char)*to_hash_length);
	
	memcpy(to_hash, skeyid_a, skeyid_a_length);
	encodeInt4Bytes(to_hash, m_id, sizeof(m_id));
	memcpy(&to_hash[skeyid_a_length+sizeof(m_id)], &message[ISAKMP_HDR_SIZE+hash_length], (*ni_length));
	memcpy(&to_hash[skeyid_a_length+sizeof(m_id)+(*ni_length)], &message[ISAKMP_HDR_SIZE+hash_length+(*ni_length)], id_payload_length);
	
	//printPayload(to_hash, to_hash_length);
	
	uint8_t* hash = NULL;
	int res1 = crypto_calculateHash(HASH_SHA256, to_hash_length, to_hash, &hash);
	if(res1 == -1){
		perror("System Error - GroupKey-Pull -> Message 1 -> CalculateHash");
		return -1;
	}
	
	res1 = memcmp(hash, &message[ISAKMP_HDR_SIZE+GENERIC_HDR_SIZE], res1);
	if(res1 != 0){
		// Invalid Hash - hashes are not equal
		perror("System Error - Hashes are not equal, dropping message");
		return -1;
	}
		
	// Extracts Ni
	*ni = (uint8_t*)malloc(sizeof(char)*(*ni_length)-GENERIC_HDR_SIZE);
	memcpy(*ni, &message[ISAKMP_HDR_SIZE+hash_length+GENERIC_HDR_SIZE], (*ni_length)-GENERIC_HDR_SIZE);
	
	
	//GroupID from ID Payload
	*group_id_length = message[ISAKMP_HDR_SIZE+hash_length+(*ni_length)+8];
	*group_id = (uint8_t*)malloc(sizeof(char)*(*group_id_length)-GENERIC_HDR_SIZE);
	memcpy(*group_id, &message[ISAKMP_HDR_SIZE+hash_length+(*ni_length)+9], (*group_id_length));

	*ni_length -= GENERIC_HDR_SIZE;

	free(to_hash);

	return 0;
}

int gdoi_process_groupkeypull_m2(uint8_t* message, uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* ni, int ni_length, uint8_t** nr, int* nr_length, KEKPolicy_nd* kek_policy, TEKPolicy_nd* tek_policy, GroupMember* GM_SAs){

	// Extract payload lengths
	int hash_payload_length = decode_2bytesToInt(message, ISAKMP_HDR_SIZE+2);
	int nr_payload_length = decode_2bytesToInt(message, ISAKMP_HDR_SIZE+hash_payload_length+2);
	int sa_payload_length = decode_2bytesToInt(message, ISAKMP_HDR_SIZE+hash_payload_length+nr_payload_length+2);

	// Determine Nr (Nounce) length
	*nr_length = nr_payload_length - GENERIC_HDR_SIZE;

	// Extract payloads from packet
	uint8_t* hash_payload = (uint8_t*)malloc(sizeof(char)*hash_payload_length);
	uint8_t* nr_payload = (uint8_t*)malloc(sizeof(char)*nr_payload_length);
	uint8_t* sa_payload = (uint8_t*)malloc(sizeof(char)*sa_payload_length);

	memcpy(hash_payload,	&message[ISAKMP_HDR_SIZE], 											hash_payload_length);	
	memcpy(nr_payload, 		&message[ISAKMP_HDR_SIZE+hash_payload_length], 						nr_payload_length);	
	memcpy(sa_payload, 		&message[ISAKMP_HDR_SIZE+hash_payload_length+nr_payload_length], 	sa_payload_length);	

	
	/* ---- VALIDATE HASH(2) ---- */
	
	// Calculate full size of concatenated to hash data
	int to_hash_length = skeyid_a_length + sizeof(m_id) + ni_length + nr_payload_length + sa_payload_length;

	// Allocate memory to concatenate to hash data
	uint8_t* to_hash = (uint8_t*)malloc(sizeof(char)*to_hash_length);

	// Concat data
	memcpy(to_hash, 															skeyid_a, 	skeyid_a_length);	// SKeyid_a
	encodeInt4Bytes(to_hash, m_id, skeyid_a_length);															// M-ID
	memcpy(&to_hash[skeyid_a_length+sizeof(m_id)], 								ni, 		ni_length);			// Ni_b
	memcpy(&to_hash[skeyid_a_length+sizeof(m_id)+ni_length], 					nr_payload, nr_payload_length);	// Nr - Payload
	memcpy(&to_hash[skeyid_a_length+sizeof(m_id)+ni_length+nr_payload_length], 	sa_payload, sa_payload_length);	// SA - Payload

	// Calculate challenge_hash
	uint8_t* challenge_hash = NULL;
	int res = crypto_calculateHash(HASH_SHA256, to_hash_length, to_hash, &challenge_hash);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Process Message 2 -> CalculateHash");
		return -1;
	}


	// Evaluate challenge 
	res = memcmp(challenge_hash, &hash_payload[GENERIC_HDR_SIZE], res);
	if(res != 0){
		// Invalid Hash - hashes are not equal
		perror("System Error - Hashes are not equal, dropping message");
		return -1;
	}

	/* ---- EXTRACT NR NOUNCE ---- */		// TODO: Check if Nr != NULL -> free(ni);

	// Extract Nr nouce to external pointer 
	*nr = (uint8_t*)malloc(sizeof(char)*(*nr_length));

	memcpy(*nr, &nr_payload[GENERIC_HDR_SIZE], *nr_length);

	/* ---- INTERPRET SA PAYLOAD ---- */
	// Interpret first SA Attribute
	int sa_attribute_next_p = decode_2bytesToInt(sa_payload, 12);
	int index = 16;	// 0-Index of first SA Attribute Payload		
	int p_index;
	int cur_p_length;

	// Control number of SA Attr payloads existing
	int n_kek = 0;
	int n_tek = 0;
	int n_gap = 0;

	do{
		p_index = index;
		cur_p_length = decode_2bytesToInt(sa_payload, index+2);
		if(sa_attribute_next_p == NP_SAKEK){
			// TODO: General SAKEK payload processing
			// SAKEK Policy reconstruction - go step-by-step over packet until reach end

			// Allocate space to new KEK policy
			*kek_policy = (KEKPolicy_nd)malloc(sizeof(ListNode_sakek_policy));
			if(*kek_policy == NULL){
				perror("System Error - Memory exausted -> Malloc KEK policy");
				return -1;
			}

			
			if((*GM_SAs).kek == NULL){
				(*GM_SAs).kek = (KEK_SA_nd)malloc(sizeof(ListNode_keksa));
			}else{
				//free((*GM_SAs).kek);
				(*GM_SAs).kek = (KEK_SA_nd)malloc(sizeof(ListNode_keksa));
			}

			printPayload(&sa_payload[p_index], 20);

			p_index += 8; 						// Jump to SRC ID Data Len
			p_index += sa_payload[p_index];		// Add SRC ID data length
			p_index += 1 + 3;					// Add previous length field + jump to DST ID Data Len
			p_index += sa_payload[p_index] + 1;	// Add DST ID data length + length field


			// Allocate memory for the spi
			if((*GM_SAs).kek->kek_sa.spi == NULL){
				(*GM_SAs).kek->kek_sa.spi = (uint8_t*)malloc(sizeof(char)*16);
				(*GM_SAs).kek->kek_sa.spi_size = 16;
			}else{
				//free((*GM_SAs).kek->kek_sa.spi);
				(*GM_SAs).kek->kek_sa.spi = (uint8_t*)malloc(sizeof(char)*16);
				(*GM_SAs).kek->kek_sa.spi_size = 16;
			}

			if((*GM_SAs).kek->kek_sa.spi){
				// Copy SPI
				memcpy((*GM_SAs).kek->kek_sa.spi, &sa_payload[p_index], 16);
			}
			
			p_index += 16 + 4;					// Add SPI + RESERVED2

			while(p_index < cur_p_length){
				uint16_t at = (uint16_t)decode_2bytesToInt(sa_payload, p_index);
				if(checkIfBitIsSet(at, 15)){
					// TV Format
					at = modify2Byte(at, 15, 0);
					if(at == 1){
						// KEK_MANAGEMENT_ALGORITHM
						(*kek_policy)->KEK_Policy.kek_management_algorithm = decode_2bytesToInt(sa_payload, p_index);
					}else if(at == 2){
						// KEK_ALGORITHM
						(*kek_policy)->KEK_Policy.kek_algorithm = decode_2bytesToInt(sa_payload, p_index);
					}else if(at == 3){
						// KEK_KEY_LENGTH
						(*kek_policy)->KEK_Policy.kek_key_length = decode_2bytesToInt(sa_payload, p_index);
					}else if(at == 5){
						// SIG_HASH_ALGORITHM
						(*kek_policy)->KEK_Policy.sig_hash_algorithm = decode_2bytesToInt(sa_payload, p_index);
					}else if(at == 6){
						// SIG_ALGORITHM
						(*kek_policy)->KEK_Policy.sig_algorithm = decode_2bytesToInt(sa_payload, p_index);
					}else if(at == 7){
						// SIG_KEY_LENGTH
						(*kek_policy)->KEK_Policy.sig_key_length = decode_2bytesToInt(sa_payload, p_index);
					}else{
						// Not implemented / Error
						perror("Not implemented yet");
						return -1;
					}
					p_index += TV_LENGTH;
				}else{
					// TODO: Generalize to other attributes
					// TLV Format
					int at_length = decode_2bytesToInt(sa_payload, p_index+2);
					if(at == 4){
						(*kek_policy)->KEK_Policy.kek_key_lifetime = decode_4bytesToInt(sa_payload, p_index);
					}else{
						// Not implemented / Error
						perror("Not implemented yet");
						return -1;
					}
					p_index += TV_LENGTH+at_length;
				}
			}
			n_kek++;
		}else if(sa_attribute_next_p == NP_SATEK){
			// TODO: Not implemented yet

			perror("Not implemented yet");
			continue;
		}else if(sa_attribute_next_p == NP_GAP){
			// TODO: Not implemented yet
			perror("Not implemented yet");
			continue;
		}
		sa_attribute_next_p = sa_payload[index];
		index += decode_2bytesToInt(sa_payload, index+2);
	}while(sa_attribute_next_p != NP_LASTPAYLOAD);

	free(hash_payload);
	free(nr_payload);
	free(sa_payload);
	free(to_hash);
	free(challenge_hash);

	return 0;
}

int gdoi_process_groupkeypull_m3(uint8_t* message, uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* ni, int ni_length, uint8_t* nr, int nr_length){
	

	// Extract payload lengths
	int hash_payload_length = decode_2bytesToInt(message, ISAKMP_HDR_SIZE+2);
	//TODO: GAP payload

	// Extract payloads from packet
	uint8_t* hash_payload = (uint8_t*)malloc(sizeof(char)*hash_payload_length);
	memcpy(hash_payload,	&message[ISAKMP_HDR_SIZE], 											hash_payload_length);	


	/* ---- VALIDATE HASH(3) ---- */
	
	// Calculate full size of concatenated to hash data
	int to_hash_length = skeyid_a_length + sizeof(m_id) + ni_length + nr_length;

	// Allocate memory to concatenate to hash data
	uint8_t* to_hash = (uint8_t*)malloc(sizeof(char)*to_hash_length);

	// Concat data
	memcpy(to_hash, 															skeyid_a, 	skeyid_a_length);	// SKeyid_a
	encodeInt4Bytes(to_hash, m_id, skeyid_a_length);															// M-ID
	memcpy(&to_hash[skeyid_a_length+sizeof(m_id)], 								ni, 		ni_length);			// Ni_b
	memcpy(&to_hash[skeyid_a_length+sizeof(m_id)+ni_length], 					nr,			nr_length);			// Nr_b

	// Calculate challenge_hash
	uint8_t* challenge_hash = NULL;
	int res = crypto_calculateHash(HASH_SHA256, to_hash_length, to_hash, &challenge_hash);
	if(res == -1){
		perror("System Error - GroupKey-Pull -> Process Message 3 -> CalculateHash");
		return -1;
	}

	// Evaluate challenge 
	res = memcmp(challenge_hash, &hash_payload[GENERIC_HDR_SIZE], res);
	if(res != 0){
		// Invalid Hash - hashes are not equal
		perror("System Error - Hashes are not equal, dropping message");
		return -1;
	}
	
	

	return 0;
}

int gdoi_process_groupkeypull_m4(uint8_t* message, uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id){
	
}