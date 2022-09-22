#ifndef GDOI_H__
#define GDOI_H__

#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <netinet/in.h> 

#include <openssl/sha.h>

#include "sa.h"
#include "isakmp.h"
#include "crypto.h"

#define GK_PULL				1
#define GK_PUSH				2

#define TV_LENGTH			4

int gdoi_createPayloadIsakmp_HDR(uint8_t* icookie, uint8_t* rcookie, uint8_t next_payload, uint8_t versions, uint8_t extype, uint8_t flags, uint32_t m_id, uint32_t length, uint8_t** dest, int debug);
int gdoi_createPayloadHash(uint8_t next_payload, uint16_t payload_length, uint8_t* hash_data, uint8_t** dest, int debug);
int gdoi_createPayloadNonce(uint8_t next_payload, uint16_t payload_length, uint8_t* nonce_data, uint8_t** dest, int debug);
int gdoi_createPayloadId(uint8_t next_payload, uint16_t payload_length, uint8_t id_type, uint8_t* id_data_payload, uint8_t** dest, int debug);
int gdoi_createSAKEK_Payload(int gk_protocol, uint8_t next_payload, uint8_t protocol, uint8_t src_id_type, uint16_t src_id_port, uint8_t src_id_len, uint8_t* src_id_data, uint8_t dst_id_type, uint16_t dst_id_port, uint8_t dst_id_len, uint8_t* dst_id_data, uint8_t* spi, KEKPolicy_nd sa_kek, GroupMember* GM_SAs ,uint8_t** dest, int debug);
int gdoi_createSATEK_Payload(int protocol_id, uint8_t oid_length, uint8_t* oid, uint16_t oid_specific_payload_length, uint8_t* oid_specific_payload, uint32_t spi, uint16_t auth_alg, uint16_t enc_alg, uint32_t remain_lifetime, int sa_data_attributes_length, uint8_t* sa_data_attributes, uint8_t** dest, int debug);
int gdoi_createPayloadSA(uint8_t next_payload, uint32_t doi, uint32_t situation, uint16_t sa_attribute_next_p, uint8_t* sa_attributes, int sa_attributes_length, uint8_t** dest, int debug);
int gdoi_createKD_Payload(uint8_t next_payload, int number_of_keys, uint8_t* key_packets, int key_packets_size, uint8_t** dest);

int gdoi_createKeyPacket_KEK(int kd_type, int spi_size, uint8_t* spi, int key_data_size, uint8_t* key_data, int iv_data_size, uint8_t* iv_data, uint8_t** dest, int debug);
int gdoi_createKeyPacket_TEK(int kd_type, int spi_size, uint8_t* spi, int key_data_size, uint8_t* key_data, int salt_data_size, uint8_t* salt_data, uint8_t** dest, int debug);

int rgoose_createPayloadIdData(uint8_t oid_length, uint8_t* oid, uint16_t oid_specific_payload_length, uint8_t* oid_specific_payload, uint8_t** dest, int debug);

int gdoi_create_groupkeypull_m1(uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* oid, int oid_length, int id_type, uint8_t** message, uint8_t** dest_ni, int* dest_ni_length, int debug);
int gdoi_create_groupkeypull_m2(uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* ni, int ni_length, uint32_t doi, uint32_t situation, uint16_t sa_attribute_next_p, KEKPolicy_nd sa_kek, TEKPolicy_nd sa_tek, GroupMember* GM_SAs, uint8_t** message, uint8_t** nr, int* nr_length, int debug);
int gdoi_create_groupkeypull_m3(uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* ni, int ni_length, uint8_t* nr, int nr_length, uint8_t** message, int debug);
int gdoi_create_groupkeypull_m4(uint8_t* icookie, uint8_t* rcookie, uint8_t* skeyid_a, int skeyid_a_length, uint32_t m_id, uint8_t* ni, int ni_length, uint8_t* nr, int nr_length, uint8_t* seq_payload, int seq_length, uint8_t* kd_payload, int kd_length, uint8_t** message, int debug);
#endif /* gdoi.h */