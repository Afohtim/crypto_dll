#include <iostream>
#include "DES.h"
#include "Blowfish.h"
#include "Blowfish.h"
#include "Kalyna.h"
#include "tests.h"



using namespace std;

void aes_tests()
{
	std::cout << "AES:\n";
	std::cout << (test1() ? "OK" : "FAILED") << '\n';
	std::cout << (test_aes("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a") ? "OK" : "FAILED") << '\n';
	std::cout << (test_aes("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191") ? "OK" : "FAILED") << '\n';
	std::cout << (test_aes("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089") ? "OK" : "FAILED") << '\n';
	std::cout << (test_aes("00112233445566778899aabbccddeeff", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "8ea2b7ca516745bfeafc49904b496089") ? "FAILED" : "OK") << '\n';

	srand(time(NULL));

	std::cout << "encrypting 100 kb of random data\n";

	std::cout << "key size = 128| " << time_test_aes(6400, "000102030405060708090a0b0c0d0e0f") << " seconds\n";
	std::cout << "key size = 192| " << time_test_aes(6400, "000102030405060708090a0b0c0d0e0f1011121314151617") << " seconds\n";
	std::cout << "key size = 256| " << time_test_aes(6400, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4") << " seconds\n";
}

void kalyna_tests()
{
	std::cout << "\nKalyna\n";
	std::cout << (test_kalyna("000102030405060708090A0B0C0D0E0F", "101112131415161718191A1B1C1D1E1F", "81BF1C7D779BAC20E1C9EA39B4D2AD06") ? "OK\n" : "FAILED\n");
	std::cout << (test_kalyna("0F0E0D0C0B0A09080706050403020100", "7291EF2B470CC7846F09C2303973DAD7", "1F1E1D1C1B1A19181716151413121110") ? "OK\n" : "FAILED\n");

	std::cout << "encrypting 100 kb of random data\n";

	std::cout << "key size = 128| " << time_test_kalyna(6400, "000102030405060708090A0B0C0D0E0F") << " seconds\n";
}

void des_tests()
{
	uint64_t des_key = rand();
	DES::keygen(des_key);
	uint64_t encrypted = DES::encrypt(0);
	uint64_t decrypted = DES::decrypt(encrypted);
	cout << encrypted << ' ' << decrypted << '\n';
}

void blowfish_tests()
{
	Blowfish::set_key("dsjkfaisulh");
	std::vector<uint32_t> original_message, message;
	for (int i = 0; i < 10; ++i)
	{
		original_message.push_back(rand());
		message.push_back(original_message.back());
	}
	for (int i = 0; i < 10; ++i)
	{
		Blowfish::cipher(message);
		//Blowfish::set_key("fasdfsds");
		Blowfish::inv_cipher(message);
	}
	std::cout << "Blowfish:\n";
	for (int i = 0; i < 10; ++i)
	{
		std::cout << (message[i] == original_message[i] ? "OK " : "FAILED ");
	}
	std::cout << '\n';
}

int main()
{
	aes_tests();
	kalyna_tests();
	des_tests();
	blowfish_tests();
	return 0;
}