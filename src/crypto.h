#ifndef CRYPTO_H__
#define CRYPTO_H__


#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <netinet/in.h> 
#include <time.h>

#include <openssl/sha.h>

#include "isakmp.h"


int crypto_generateNonceByteStream(int length, uint8_t** dest);
int crypto_SHA256(uint8_t* data, int length, uint8_t* dest);
int crypto_calculateHash(int alg, int length, uint8_t* data, uint8_t** dest);


#endif /* crypto.h */