/*
 * *** COServer.Security.Cryptography - Closed Source ***
 * Copyright (C) 2014 - 2015 Jean-Philippe Boivin
 *
 * Please read the WARNING, DISCLAIMER and PATENTS
 * sections in the LICENSE file.
 */

#include "tqcipher_avx2.h"
#include <string.h> // memset
#include <assert.h>

// ***********************************************************************
// * AVX2 extensions
// ***********************************************************************
static __forceinline __m256i
_mm256_slli_epi8(__m256i __a, int __count)
{
    static const uint8_t MASKS[] =
        { 0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80 };

    __m256i mask = _mm256_set1_epi8(MASKS[__count]);
    return _mm256_and_si256(_mm256_slli_epi16(__a, __count), mask);
}

static __forceinline __m256i
_mm256_srli_epi8(__m256i __a, int __count)
{
    static const uint8_t MASKS[] =
        { 0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01 };

    __m256i mask    = _mm256_set1_epi8(MASKS[__count]);
    return _mm256_and_si256(_mm256_srli_epi16(__a, __count), mask);
}

// ***********************************************************************
// ***********************************************************************

TqCipher_AVX2 :: TqCipher_AVX2()
    : mEnCounter(0), mDeCounter(0),
      mUsingAltKey(false)
{
    // security purpose only...
    memset(mKey, 0, sizeof(mKey));
    memset(mAltKey, 0, sizeof(mAltKey));
}

// there is a bug with VS2013 optimization algorithm, making the second key generation fails
#pragma optimize( "", off )
void
TqCipher_AVX2 :: generateKey(uint32_t aP, uint32_t aG)
{
    uint8_t* p = (uint8_t*)&aP;
    uint8_t* g = (uint8_t*)&aG;

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE / 2) + (sizeof(__m256i) - 1);

    for (size_t i = 0, len = (KEY_SIZE  / 2); i < len; ++i)
    {
        key1[i] = p[0];
        key2[i] = g[0];
        p[0] = (uint8_t)((p[1] + (uint8_t)(p[0] * p[2])) * p[0] + p[3]);
        g[0] = (uint8_t)((g[1] - (uint8_t)(g[0] * g[2])) * g[0] + g[3]);
    }

    memcpy(key1 + KEY_SIZE / 2, key1, sizeof(__m256i) - 1);
    memcpy(key2 + KEY_SIZE / 2, key2, sizeof(__m256i) - 1);
}
#pragma optimize( "", on ) 

void
TqCipher_AVX2 :: generateAltKey(int32_t aA, int32_t aB)
{
    uint32_t x = (uint32_t)(((aA + aB) ^ 0x4321) ^ aA);
    uint32_t y = x * x;

    uint8_t* tmpKey1 = (uint8_t*)&x;
    uint8_t* tmpKey2 = (uint8_t*)&y;

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2) + (sizeof(__m256i) - 1);
    uint8_t* altKey1 = mAltKey;
    uint8_t* altKey2 = altKey1 + (KEY_SIZE  / 2) + (sizeof(__m256i) - 1);

    for (size_t i = 0, len = (KEY_SIZE / 2); i < len; ++i)
    {
        altKey1[i] = (uint8_t)(key1[i] ^ tmpKey1[(i % sizeof(x))]);
        altKey2[i] = (uint8_t)(key2[i] ^ tmpKey2[(i % sizeof(y))]);
    }

    memcpy(altKey1 + KEY_SIZE / 2, altKey1, sizeof(__m256i) - 1);
    memcpy(altKey2 + KEY_SIZE / 2, altKey2, sizeof(__m256i) - 1);

    mUsingAltKey = true;
    mEnCounter = 0;
}

void
TqCipher_AVX2 :: encrypt(uint8_t* aBuf, size_t aLen)
{
    assert(aBuf != nullptr);
    assert(aLen > 0);

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2) + (sizeof(__m256i) - 1);

    uint8_t tmp[sizeof(__m256i)];
    __m256i* buf = (__m256i*)aBuf;
    __m256i x, y, z, w;

    z = _mm256_set1_epi8(0xABU);
    for (size_t i = 0, count = aLen / sizeof(__m256i); i < count; ++i)
    {
        x = _mm256_loadu_si256((__m256i*)&key1[(uint8_t)mEnCounter]);
        if (0x100 - mEnCounter % 0x100 >= sizeof(__m256i))
            y = _mm256_set1_epi8(key2[(uint8_t)(mEnCounter >> 8)]);
        else
        {
            size_t n = 0x100 - mEnCounter % 0x100;
            memset(tmp, key2[(uint8_t)(mEnCounter >> 8)], n);
            memset(&tmp[n], key2[(uint8_t)(mEnCounter >> 8) + 1], sizeof(__m256i) - n);
            y = _mm256_loadu_si256((__m256i*)tmp);
        }

        w = _mm256_loadu_si256(&buf[i]);

        w = _mm256_xor_si256(w, z);
        w = _mm256_or_si256(_mm256_slli_epi8(w, 4), _mm256_srli_epi8(w, 4));
        w = _mm256_xor_si256(_mm256_xor_si256(w, x), y);

        _mm256_storeu_si256(&buf[i], w);

        mEnCounter += sizeof(__m256i);
    }

    for (size_t i = aLen - (aLen % sizeof(__m256i)); i < aLen; ++i)
    {
        aBuf[i] ^= UINT8_C(0xAB);
        aBuf[i] = (uint8_t)(aBuf[i] << 4 | aBuf[i] >> 4);
        aBuf[i] ^= key1[(uint8_t)mEnCounter];
        aBuf[i] ^= key2[(uint8_t)(mEnCounter >> 8)];
        ++mEnCounter;
    }
}

void
TqCipher_AVX2 :: decrypt(uint8_t* aBuf, size_t aLen)
{
    assert(aBuf != nullptr);
    assert(aLen > 0);

    uint8_t* key1 = mUsingAltKey ? mAltKey : mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2) + (sizeof(__m256i) - 1);

    uint8_t tmp[sizeof(__m256i)];
    __m256i* buf = (__m256i*)aBuf;
    __m256i x, y, z, w;

    z = _mm256_set1_epi8(0xABU);
    for (size_t i = 0, count = aLen / sizeof(__m256i); i < count; ++i)
    {
        x = _mm256_loadu_si256((__m256i*)&key1[(uint8_t)mDeCounter]);
        if (0x100 - mDeCounter % 0x100 >= sizeof(__m256i))
            y = _mm256_set1_epi8(key2[(uint8_t)(mDeCounter >> 8)]);
        else
        {
            size_t n = 0x100 - mDeCounter % 0x100;
            memset(tmp, key2[(uint8_t)(mDeCounter >> 8)], n);
            memset(&tmp[n], key2[(uint8_t)(mDeCounter >> 8) + 1], sizeof(__m256i) - n);
            y = _mm256_loadu_si256((__m256i*)tmp);
        }

        w = _mm256_loadu_si256(&buf[i]);

        w = _mm256_xor_si256(w, z);
        w = _mm256_or_si256(_mm256_slli_epi8(w, 4), _mm256_srli_epi8(w, 4));
        w = _mm256_xor_si256(_mm256_xor_si256(w, x), y);

        _mm256_storeu_si256(&buf[i], w);

        mDeCounter += sizeof(__m256i);
    }

    for (size_t i = aLen - (aLen % sizeof(__m256i)); i < aLen; ++i)
    {
        aBuf[i] ^= UINT8_C(0xAB);
        aBuf[i] = (uint8_t)(aBuf[i] << 4 | aBuf[i] >> 4);
        aBuf[i] ^= key1[(uint8_t)mDeCounter];
        aBuf[i] ^= key2[(uint8_t)(mDeCounter >> 8)];
        ++mDeCounter;
    }
}