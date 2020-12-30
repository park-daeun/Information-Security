#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "hash.h"

int main() {
	unsigned char plain_text[4098] = { 0, }; //평문 저장소
	unsigned char cipher_text[4098]; //암호문 저장소

	unsigned int num; //암호문 길이

	char calc_hash[65]; //해시 값 저장소
	char* path = "message.txt";
	int result;

	unsigned char sign[256]; //디지털 서명 저장소
	int sign_len; //디지털 서명 길이

	//암호화할 메시지 가져오기
	FILE* r_file = fopen("message.txt", "r");
	if (!r_file)return -1;
	fread(plain_text, sizeof(plain_text), 1, r_file);
	fclose(r_file);
	//printf("암호화할 메시지는 다음과 같습니다.\n%s\n", plain_text);

	//ML Team의 공개 키 가져오기
	FILE* ML_key_f = fopen("MLTeamPublic.key", "r");
	if (ML_key_f == NULL) {
		printf("'MLTeamPublic.key'를 찾을 수 없습니다.\n");
		return 0;
	}
	RSA* ML_public_key = PEM_read_RSA_PUBKEY(ML_key_f, NULL, NULL, NULL);
	if (ML_public_key == NULL) {
		printf("Read Public Key for RSA Error\n");
		return 0;
	}
	fclose(ML_key_f);

	//나의 개인 키 가져오기
	FILE* my_key_f = fopen("myPrivate.key", "r");
	if (my_key_f == NULL) {
		printf("'myPrivate.key'를 찾을 수 없습니다.\n");
		return 0;
	}
	RSA* my_private_key = PEM_read_RSAPrivateKey(my_key_f, NULL, NULL, NULL);
	if (my_private_key == NULL) {
		printf("Read Private Key for RSA Error\n");
		return 0;
	}
	fclose(my_key_f);

	//메시지의 해시 값 구하기
	result = calc_sha256(path, calc_hash);
	//printf("메시지의 해시 값은 다음과 같습니다.\n%s\n", calc_hash);

	//메시지 암호화하기
	memset(cipher_text, 0x00, sizeof(cipher_text));
	num = RSA_public_encrypt(strlen(plain_text), plain_text, cipher_text, ML_public_key, RSA_PKCS1_PADDING);
	//printf("암호문은 다음과 같습니다.\n%s\n", cipher_text);

	FILE* w_file = fopen("cipher_text.txt", "w");
	fwrite(cipher_text, num, 1, w_file);
	printf("암호문을 저장했습니다.\n");
	fclose(w_file);

	//해시 값 서명 작성하기
	memset(sign, 0x00, sizeof(sign));
	sign_len = RSA_private_encrypt(sizeof(calc_hash), calc_hash, sign, my_private_key, RSA_PKCS1_PADDING);
	if (sign_len < 1) {
		printf("rsa private encrypt error\n");
		return;
	}
	//printf("서명은 다음과 같습니다.\n%s\n", sign);

	FILE* s_file = fopen("signature.txt", "w");
	fwrite(sign, sign_len, 1, s_file);
	printf("서명을 저장했습니다.\n");
	fclose(s_file);

	return 0;
}