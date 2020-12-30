#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "hash.h"

int main() {
	unsigned char plain_text[4098] = { 0, }; //�� �����
	unsigned char cipher_text[4098]; //��ȣ�� �����

	unsigned int num; //��ȣ�� ����

	char calc_hash[65]; //�ؽ� �� �����
	char* path = "message.txt";
	int result;

	unsigned char sign[256]; //������ ���� �����
	int sign_len; //������ ���� ����

	//��ȣȭ�� �޽��� ��������
	FILE* r_file = fopen("message.txt", "r");
	if (!r_file)return -1;
	fread(plain_text, sizeof(plain_text), 1, r_file);
	fclose(r_file);
	//printf("��ȣȭ�� �޽����� ������ �����ϴ�.\n%s\n", plain_text);

	//ML Team�� ���� Ű ��������
	FILE* ML_key_f = fopen("MLTeamPublic.key", "r");
	if (ML_key_f == NULL) {
		printf("'MLTeamPublic.key'�� ã�� �� �����ϴ�.\n");
		return 0;
	}
	RSA* ML_public_key = PEM_read_RSA_PUBKEY(ML_key_f, NULL, NULL, NULL);
	if (ML_public_key == NULL) {
		printf("Read Public Key for RSA Error\n");
		return 0;
	}
	fclose(ML_key_f);

	//���� ���� Ű ��������
	FILE* my_key_f = fopen("myPrivate.key", "r");
	if (my_key_f == NULL) {
		printf("'myPrivate.key'�� ã�� �� �����ϴ�.\n");
		return 0;
	}
	RSA* my_private_key = PEM_read_RSAPrivateKey(my_key_f, NULL, NULL, NULL);
	if (my_private_key == NULL) {
		printf("Read Private Key for RSA Error\n");
		return 0;
	}
	fclose(my_key_f);

	//�޽����� �ؽ� �� ���ϱ�
	result = calc_sha256(path, calc_hash);
	//printf("�޽����� �ؽ� ���� ������ �����ϴ�.\n%s\n", calc_hash);

	//�޽��� ��ȣȭ�ϱ�
	memset(cipher_text, 0x00, sizeof(cipher_text));
	num = RSA_public_encrypt(strlen(plain_text), plain_text, cipher_text, ML_public_key, RSA_PKCS1_PADDING);
	//printf("��ȣ���� ������ �����ϴ�.\n%s\n", cipher_text);

	FILE* w_file = fopen("cipher_text.txt", "w");
	fwrite(cipher_text, num, 1, w_file);
	printf("��ȣ���� �����߽��ϴ�.\n");
	fclose(w_file);

	//�ؽ� �� ���� �ۼ��ϱ�
	memset(sign, 0x00, sizeof(sign));
	sign_len = RSA_private_encrypt(sizeof(calc_hash), calc_hash, sign, my_private_key, RSA_PKCS1_PADDING);
	if (sign_len < 1) {
		printf("rsa private encrypt error\n");
		return;
	}
	//printf("������ ������ �����ϴ�.\n%s\n", sign);

	FILE* s_file = fopen("signature.txt", "w");
	fwrite(sign, sign_len, 1, s_file);
	printf("������ �����߽��ϴ�.\n");
	fclose(s_file);

	return 0;
}