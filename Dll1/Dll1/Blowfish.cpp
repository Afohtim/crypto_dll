#include "pch.h"
#include "Blowfish.h"
#include "Blowfish_lookup_tables.h"


namespace Blowfish
{

	int gcd(int x, int y)
	{
		if (x < y)
			std::swap(x, y);
		while (x != 0 && y != 0)
		{
			x %= y;
			std::swap(x, y);
		}
		return x;
	}


	uint32_t f(uint32_t x)
	{
		uint32_t h = S[0][x >> 24] + S[1][x >> 16 & 0xff];
		return (h ^ S[2][x >> 8 & 0xff]) + S[3][x & 0xff];
	}

	void cipherLR(uint32_t& L, uint32_t& R)
	{
		for (int i = 0; i < 16; ++i)
		{
			L ^= P[i];
			R ^= f(L);
			std::swap(L, R);
		}

		std::swap(L, R);

		R ^= P[16];
		L ^= P[17];
	}

	void cipher(std::vector<uint32_t>& text)
	{
		for (int i = 0; i < text.size() / 2; ++i)
		{
			cipherLR(text[2 * i], text[2 * i + 1]);
		}

	}

	void inv_cipherLR(uint32_t& L, uint32_t& R)
	{
		for (int i = 0; i < 16; ++i)
		{
			L ^= P[17 - i];
			R ^= f(L);
			std::swap(L, R);
		}

		std::swap(L, R);

		R ^= P[1];
		L ^= P[0];
	}

	void inv_cipher(std::vector<uint32_t>& text)
	{
		for (int i = 0; i < text.size() / 2; ++i)
		{
			inv_cipherLR(text[2 * i], text[2 * i + 1]);
		}
	}


	void set_key(std::string key)
	{
		std::copy(std::begin(initial_P), std::end(initial_P), P);
		for (int i = 0; i < 4; ++i)
		{
			for (int j = 0; j < 256; ++j)
			{
				S[i][j] = initial_S[i][j];
			}
		}

		std::vector<uint32_t> buffer(key.size() / gcd(key.size(), 4));

		for (int i = 0; i < buffer.size(); ++i)
		{
			buffer[i] = ((uint32_t)key[(i * 4) % key.size()]) << 24 |
				((uint32_t)key[(i * 4 + 1) % key.size()]) << 16 |
				((uint32_t)key[(i * 4 + 2) % key.size()]) << 8 |
				((uint32_t)key[(i * 4 + 3) % key.size()]);
		}

		for (int i = 0; i < P_size; ++i)
		{
			P[i] ^= buffer[i % buffer.size()];
		}

		uint32_t L = 0, R = 0;

		for (int i = 0; i < P_size / 2; ++i)
		{
			cipherLR(L, R);
			P[i * 2] = L;
			P[i * 2 + 1] = R;
		}

		for (int i = 0; i < S_size_1; ++i)
		{
			for (int j = 0; j < S_size_2 / 2; ++j)
			{
				cipherLR(L, R);

				S[i][j * 2] = L;
				S[i][j * 2 + 1] = R;

			}
		}

	}

	void cipher_blowfish(uint32_t* text, int& text_size)
	{
		std::vector<uint32_t> text_vec(text, text + text_size);
		cipher(text_vec);
		std::copy(text_vec.begin(), text_vec.end(), text);
	}

	void inv_cipher_blowfish(uint32_t* text, int& text_size)
	{
		std::vector<uint32_t> text_vec(text, text + text_size);
		inv_cipher(text_vec);
		std::copy(text_vec.begin(), text_vec.end(), text);
	}

	void set_key_blowfish(char* s, int& s_size)
	{
		std::string s_str(s, s + s_size);
		set_key(s_str);
		std::copy(s_str.begin(), s_str.end(), s);
	}
}