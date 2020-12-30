#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openssl/applink.c" 
#include "openssl/sha.h" 

int calc_sha256(char* path, char* output);
void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char* outputBuffer);

int calc_sha256(char* path, char* output) {

    FILE* file = fopen(path, "rb");
    if (!file)return -1;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    const int bufSize = 32768;
    unsigned char* buffer = (unsigned char*)malloc(bufSize);
    SHA256_CTX sha256;
    int bytesRead = 0;

    if (!buffer)return -2;

    SHA256_Init(&sha256);

    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    SHA256_Final(hash, &sha256);
    sha256_hash_string(hash, output);
    fclose(file);

    return 0;
}

void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char* outputBuffer)
{
    int i = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}