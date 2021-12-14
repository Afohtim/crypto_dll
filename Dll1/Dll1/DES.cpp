#include "pch.h"
#include "DES.h"
#include "DES_lookup_tables.h"


namespace DES
{

    uint64_t sub_key[16]; // 48 bits each


/*DES(uint64_t key)
{
    keygen(key);
}*/

    

    

    uint64_t ip(uint64_t block)
    {
        uint64_t result = 0;
        for (uint8_t i = 0; i < 64; i++)
        {
            result <<= 1;
            result |= (block >> (64 - IP[i])) & LB64_MASK;
        }
        return result;
    }

    uint64_t fp(uint64_t block)
    {
        uint64_t result = 0;
        for (uint8_t i = 0; i < 64; i++)
        {
            result <<= 1;
            result |= (block >> (64 - FP[i])) & LB64_MASK;
        }
        return result;
    }

    void feistel(uint32_t& L, uint32_t& R, uint32_t F)
    {
        uint32_t temp = R;
        R = L ^ F;
        L = temp;
    }

    uint32_t f(uint32_t R, uint64_t k)
    {
        uint64_t s_input = 0;
        for (uint8_t i = 0; i < 48; i++)
        {
            s_input <<= 1;
            s_input |= (uint64_t)((R >> (32 - EXPANSION[i])) & LB32_MASK);
        }

        s_input = s_input ^ k;

        uint32_t s_output = 0;
        for (uint8_t i = 0; i < 8; i++)
        {
            char row = (char)((s_input & (0x0000840000000000 >> 6 * i)) >> (42 - 6 * i));
            row = (row >> 4) | (row & 0x01);

            char column = (char)((s_input & (0x0000780000000000 >> 6 * i)) >> (43 - 6 * i));

            s_output <<= 4;
            s_output |= (uint32_t)(SBOX[i][16 * row + column] & 0x0f);
        }

        uint32_t f_result = 0;
        for (uint8_t i = 0; i < 32; i++)
        {
            f_result <<= 1;
            f_result |= (s_output >> (32 - PBOX[i])) & LB32_MASK;
        }

        return f_result;
    }

    void keygen(uint64_t key)
    {
        uint64_t permuted_choice_1 = 0;
        for (uint8_t i = 0; i < 56; i++)
        {
            permuted_choice_1 <<= 1;
            permuted_choice_1 |= (key >> (64 - PC1[i])) & LB64_MASK;
        }
        uint32_t C = (uint32_t)((permuted_choice_1 >> 28) & 0x000000000fffffff);
        uint32_t D = (uint32_t)(permuted_choice_1 & 0x000000000fffffff);

        for (uint8_t i = 0; i < 16; i++)
        {
            for (uint8_t j = 0; j < ITERATION_SHIFT[i]; j++)
            {
                C = (0x0fffffff & (C << 1)) | (0x00000001 & (C >> 27));
                D = (0x0fffffff & (D << 1)) | (0x00000001 & (D >> 27));
            }

            uint64_t permuted_choice_2 = (((uint64_t)C) << 28) | (uint64_t)D;

            sub_key[i] = 0;
            for (uint8_t j = 0; j < 48; j++)
            {
                sub_key[i] <<= 1;
                sub_key[i] |= (permuted_choice_2 >> (56 - PC2[j])) & LB64_MASK;
            }
        }
    }

    uint64_t des(uint64_t block, bool mode)
    {
        block = ip(block);

        uint32_t L = (uint32_t)(block >> 32) & L64_MASK;
        uint32_t R = (uint32_t)(block & L64_MASK);

        for (uint8_t i = 0; i < 16; i++)
        {
            uint32_t F = mode ? f(R, sub_key[15 - i]) : f(R, sub_key[i]);
            feistel(L, R, F);
        }

        block = (((uint64_t)R) << 32) | (uint64_t)L;
        return fp(block);
    }

    uint64_t encrypt(uint64_t block)
    {
        return des(block, false);
    }

    uint64_t decrypt(uint64_t block)
    {
        return des(block, true);
    }

    uint64_t encrypt(uint64_t block, uint64_t key)
    {
        keygen(key);
        return des(block, false);
    }

    uint64_t decrypt(uint64_t block, uint64_t key)
    {
        keygen(key);
        return des(block, true);
    }




}