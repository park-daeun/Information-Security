#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "hash.h"

int main() {
	unsigned char cipher_text[4098] = { 0, }; //암호문 저장소
	unsigned char plain_text_receiver[4098]; //복호화한 암호문 저장소

	int num; //복호화한 암호문 길이

	char calc_hash[65]; //복호화한 암호문의 해시 값 저장소
	char* path = "decrypted_text.txt";
	int result;

	char my_sign[256] = { 0, }; //수신된 서명 저장소
	unsigned char my_hash[65]; //복호화된 서명 저장소
	int my_hash_len; //복호화된 서명의 길이

	//복호화할 메시지 가져오기
	FILE* file = fopen("cipher_text.txt", "r");
	if (!file)return -1;
	fread(cipher_text, sizeof(cipher_text), 1, file);
	fclose(file);
	//printf("암호문은 다음과 같습니다\n%s\n", cipher_text);

	//ML Team의 개인 키 가져오기
	FILE* ML_key_f = fopen("MLTeamPrivate.key", "r");
	if (ML_key_f == NULL) {
		printf("'MLTeamPrivate.key'를 찾을 수 없습니다.\n");
		return 0;
	}
	RSA* ML_private_key = PEM_read_RSAPrivateKey(ML_key_f, NULL, NULL, NULL);
	if (ML_private_key == NULL) {
		printf("Read Public Key for RSA Error\n");
		return 0;
	}
	fclose(ML_key_f);

	//나의 공개 키 가져오기
	FILE* my_key_f = fopen("myPublic.key", "r");
	if (my_key_f == NULL) {
		printf("'myPublic.key'를 찾을 수 없습니다.\n");
		return 0;
	}
	RSA* my_public_key = PEM_read_RSA_PUBKEY(my_key_f, NULL, NULL, NULL);
	if (my_public_key == NULL) {
		printf("Read Private Key for RSA Error\n");
		return 0;
	}
	fclose(my_key_f);

	//메시지 복호화하기
	memset(plain_text_receiver, 0x00, sizeof(plain_text_receiver));
	num = RSA_private_decrypt(strlen(cipher_text), cipher_text, plain_text_receiver, ML_private_key, RSA_PKCS1_PADDING);
	if (num < 1) {
		printf("rsa private encrypt error %d\n",num);
		return;
	}
	//printf("복호화된 메시지는 다음과 같습니다.\n%s\n", plain_text_receiver);

	FILE* d_file = fopen("decrypted_text.txt", "w");
	fwrite(plain_text_receiver, num, 1, d_file);
	printf("복호화된 메시지를 저장했습니다.\n");
	fclose(d_file);

	//메시지의 해시 값 구하기
	result = calc_sha256(path, calc_hash);
	//printf("복호화된 메시지의 해시 값은 다음과 같습니다.\n%s\n", calc_hash);

	//수신된 서명 복호화하기
	FILE* s_file = fopen("signature.txt", "r");
	if (!s_file)return -1;
	fread(my_sign, sizeof(my_sign), 1, s_file);
	fclose(s_file);
	//printf("수신된 서명은 다음과 같습니다.\n%s\n", my_sign);

	memset(my_hash, 0x00, sizeof(my_hash));
	my_hash_len = RSA_public_decrypt(strlen(my_sign), my_sign, my_hash, my_public_key, RSA_PKCS1_PADDING);
	if (my_hash_len < 1) {
		printf("rsa private encrypt error %d\n", my_hash_len);
		return;
	}
	//printf("복호화된 서명은 다음과 같습니다.\n%s\n", my_hash);

	//해시값 서명 검증하기
	int Result;
	Result = memcmp(my_hash, calc_hash, my_hash_len); //복호화한 값이 메시지 해시값과 같은지 확인한다.
	if (!Result) printf("디지털 서명 검증이 완료되었습니다.\n");
	else printf("디지털 서명 검증에 실패하엿습니다.\n");

	return 0;
}