#include "crypto.h"

// Crypto funcs
int crypto_generateNonceByteStream(int length, uint8_t** dest){

	*dest = (uint8_t*)malloc(sizeof(char)*length);
	if(*dest == NULL){
		perror("Memory exausted");
		return -1;
	}
	
	srand ((unsigned int) time (NULL));
	
	int i;
	
	for(i=0; i<length; i++){
		(*dest)[i] = rand();
	}
	
	return length;
}


int crypto_SHA256(uint8_t* data, int length, uint8_t* dest){
	SHA256_CTX context;
    if(!SHA256_Init(&context))
        return -1;

    if(!SHA256_Update(&context, data, length))
        return -2;

    if(!SHA256_Final(dest, &context))
        return -3;

    return 1;
}

int crypto_calculateHash(int alg, int length, uint8_t* data, uint8_t** dest){
	if(alg = HASH_SHA256){
		*dest = (uint8_t*)malloc(sizeof(char)*SHA256_DIGEST_LENGTH);
		if(crypto_SHA256(data, length, *dest) == 1){
			return SHA256_DIGEST_LENGTH;
		}else{
			return -1;
		}
	}else{
		return -1;
	}
}

