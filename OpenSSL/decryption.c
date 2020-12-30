#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "hash.h"

int main() {
	unsigned char cipher_text[4098] = { 0, }; //��ȣ�� �����
	unsigned char plain_text_receiver[4098]; //��ȣȭ�� ��ȣ�� �����

	int num; //��ȣȭ�� ��ȣ�� ����

	char calc_hash[65]; //��ȣȭ�� ��ȣ���� �ؽ� �� �����
	char* path = "decrypted_text.txt";
	int result;

	char my_sign[256] = { 0, }; //���ŵ� ���� �����
	unsigned char my_hash[65]; //��ȣȭ�� ���� �����
	int my_hash_len; //��ȣȭ�� ������ ����

	//��ȣȭ�� �޽��� ��������
	FILE* file = fopen("cipher_text.txt", "r");
	if (!file)return -1;
	fread(cipher_text, sizeof(cipher_text), 1, file);
	fclose(file);
	//printf("��ȣ���� ������ �����ϴ�\n%s\n", cipher_text);

	//ML Team�� ���� Ű ��������
	FILE* ML_key_f = fopen("MLTeamPrivate.key", "r");
	if (ML_key_f == NULL) {
		printf("'MLTeamPrivate.key'�� ã�� �� �����ϴ�.\n");
		return 0;
	}
	RSA* ML_private_key = PEM_read_RSAPrivateKey(ML_key_f, NULL, NULL, NULL);
	if (ML_private_key == NULL) {
		printf("Read Public Key for RSA Error\n");
		return 0;
	}
	fclose(ML_key_f);

	//���� ���� Ű ��������
	FILE* my_key_f = fopen("myPublic.key", "r");
	if (my_key_f == NULL) {
		printf("'myPublic.key'�� ã�� �� �����ϴ�.\n");
		return 0;
	}
	RSA* my_public_key = PEM_read_RSA_PUBKEY(my_key_f, NULL, NULL, NULL);
	if (my_public_key == NULL) {
		printf("Read Private Key for RSA Error\n");
		return 0;
	}
	fclose(my_key_f);

	//�޽��� ��ȣȭ�ϱ�
	memset(plain_text_receiver, 0x00, sizeof(plain_text_receiver));
	num = RSA_private_decrypt(strlen(cipher_text), cipher_text, plain_text_receiver, ML_private_key, RSA_PKCS1_PADDING);
	if (num < 1) {
		printf("rsa private encrypt error %d\n",num);
		return;
	}
	//printf("��ȣȭ�� �޽����� ������ �����ϴ�.\n%s\n", plain_text_receiver);

	FILE* d_file = fopen("decrypted_text.txt", "w");
	fwrite(plain_text_receiver, num, 1, d_file);
	printf("��ȣȭ�� �޽����� �����߽��ϴ�.\n");
	fclose(d_file);

	//�޽����� �ؽ� �� ���ϱ�
	result = calc_sha256(path, calc_hash);
	//printf("��ȣȭ�� �޽����� �ؽ� ���� ������ �����ϴ�.\n%s\n", calc_hash);

	//���ŵ� ���� ��ȣȭ�ϱ�
	FILE* s_file = fopen("signature.txt", "r");
	if (!s_file)return -1;
	fread(my_sign, sizeof(my_sign), 1, s_file);
	fclose(s_file);
	//printf("���ŵ� ������ ������ �����ϴ�.\n%s\n", my_sign);

	memset(my_hash, 0x00, sizeof(my_hash));
	my_hash_len = RSA_public_decrypt(strlen(my_sign), my_sign, my_hash, my_public_key, RSA_PKCS1_PADDING);
	if (my_hash_len < 1) {
		printf("rsa private encrypt error %d\n", my_hash_len);
		return;
	}
	//printf("��ȣȭ�� ������ ������ �����ϴ�.\n%s\n", my_hash);

	//�ؽð� ���� �����ϱ�
	int Result;
	Result = memcmp(my_hash, calc_hash, my_hash_len); //��ȣȭ�� ���� �޽��� �ؽð��� ������ Ȯ���Ѵ�.
	if (!Result) printf("������ ���� ������ �Ϸ�Ǿ����ϴ�.\n");
	else printf("������ ���� ������ �����Ͽ����ϴ�.\n");

	return 0;
}