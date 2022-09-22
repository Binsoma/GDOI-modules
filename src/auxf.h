#ifndef AUXF_H__
#define AUXF_H__

#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <netinet/in.h> 

int decode_2bytesToInt(uint8_t* buffer, int index);
int decode_4bytesToInt(uint8_t* buffer, int index);
void encodeInt2Bytes(uint8_t* buffer, uint16_t value, int index);
void encodeInt4Bytes(uint8_t* buffer, uint32_t value, int index);
uint8_t* hexStringToBytes(char hex[], size_t len);
void printPayload(uint8_t* buffer, int length);
uint16_t modify2Byte(uint16_t n, uint16_t p, uint16_t b);
int checkIfBitIsSet(int var, int pos);


#endif /* auxf.h */


