/*
 * *** COServer.Security.Cryptography - Closed Source ***
 * Copyright (C) 2014 - 2015 Jean-Philippe Boivin
 *
 * Please read the WARNING, DISCLAIMER and PATENTS
 * sections in the LICENSE file.
 */

#include "tqcipher_sse2.h"
#include <string.h> // memset
#include <assert.h>

// ***********************************************************************
// * SSE2 extensions
// ***********************************************************************
static __forceinline __m128i
_mm_slli_epi8(__m128i __a, int __count)
{
    static const uint8_t MASKS[] =
        { 0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80 };

    __m128i mask = _mm_set1_epi8(MASKS[__count]);
    return _mm_and_si128(_mm_slli_epi16(__a, __count), mask);
}

static __forceinline __m128i
_mm_srli_epi8(__m128i __a, int __count)
{
    static const uint8_t MASKS[] =
        { 0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01 };

    __m128i mask    = _mm_set1_epi8(MASKS[__count]);
    return _mm_and_si128(_mm_srli_epi16(__a, __count), mask);
}

// ***********************************************************************
// ***********************************************************************

TqCipher_SSE2 :: TqCipher_SSE2()
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
TqCipher_SSE2 :: generateKey(uint32_t aP, uint32_t aG)
{
    uint8_t* p = (uint8_t*)&aP;
    uint8_t* g = (uint8_t*)&aG;

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE / 2) + (sizeof(__m128i) - 1);

    for (size_t i = 0, len = (KEY_SIZE  / 2); i < len; ++i)
    {
        key1[i] = p[0];
        key2[i] = g[0];
        p[0] = (uint8_t)((p[1] + (uint8_t)(p[0] * p[2])) * p[0] + p[3]);
        g[0] = (uint8_t)((g[1] - (uint8_t)(g[0] * g[2])) * g[0] + g[3]);
    }

    memcpy(key1 + KEY_SIZE / 2, key1, sizeof(__m128i) - 1);
    memcpy(key2 + KEY_SIZE / 2, key2, sizeof(__m128i) - 1);
}
#pragma optimize( "", on ) 

void
TqCipher_SSE2 :: generateAltKey(int32_t aA, int32_t aB)
{
    uint32_t x = (uint32_t)(((aA + aB) ^ 0x4321) ^ aA);
    uint32_t y = x * x;

    uint8_t* tmpKey1 = (uint8_t*)&x;
    uint8_t* tmpKey2 = (uint8_t*)&y;

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2) + (sizeof(__m128i) - 1);
    uint8_t* altKey1 = mAltKey;
    uint8_t* altKey2 = altKey1 + (KEY_SIZE  / 2) + (sizeof(__m128i) - 1);

    for (size_t i = 0, len = (KEY_SIZE / 2); i < len; ++i)
    {
        altKey1[i] = (uint8_t)(key1[i] ^ tmpKey1[(i % sizeof(x))]);
        altKey2[i] = (uint8_t)(key2[i] ^ tmpKey2[(i % sizeof(y))]);
    }

    memcpy(altKey1 + KEY_SIZE / 2, altKey1, sizeof(__m128i) - 1);
    memcpy(altKey2 + KEY_SIZE / 2, altKey2, sizeof(__m128i) - 1);

    mUsingAltKey = true;
    mEnCounter = 0;
}

void
TqCipher_SSE2 :: encrypt(uint8_t* aBuf, size_t aLen)
{
    assert(aBuf != nullptr);
    assert(aLen > 0);

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE / 2) + (sizeof(__m128i) - 1);

    uint8_t tmp[sizeof(__m128i)];
    __m128i* buf = (__m128i*)aBuf;
    __m128i x, y, z, w;

    z = _mm_set1_epi8(0xAB);
    for (size_t i = 0, count = aLen / sizeof(__m128i); i < count; ++i)
    {
        x = _mm_loadu_si128((__m128i*)&key1[(uint8_t)mEnCounter]);
        if (0x100 - mEnCounter % 0x100 >= sizeof(__m128i))
            y = _mm_set1_epi8(key2[(uint8_t)(mEnCounter >> 8)]);
        else
        {
            size_t n = 0x100 - mEnCounter % 0x100;
            memset(tmp, key2[(uint8_t)(mEnCounter >> 8)], n);
            memset(&tmp[n], key2[(uint8_t)(mEnCounter >> 8) + 1], sizeof(__m128i) - n);
            y = _mm_loadu_si128((__m128i*)tmp);
        }

        w = _mm_loadu_si128(&buf[i]);

        w = _mm_xor_si128(w, z);
        w = _mm_or_si128(_mm_slli_epi8(w, 4), _mm_srli_epi8(w, 4));
        w = _mm_xor_si128(_mm_xor_si128(w, x), y);

        _mm_storeu_si128(&buf[i], w);

        mEnCounter += sizeof(__m128i);
    }

    for (size_t i = aLen - (aLen % sizeof(__m128i)); i < aLen; ++i)
    {
        aBuf[i] ^= UINT8_C(0xAB);
        aBuf[i] = (uint8_t)(aBuf[i] << 4 | aBuf[i] >> 4);
        aBuf[i] ^= key1[(uint8_t)mEnCounter];
        aBuf[i] ^= key2[(uint8_t)(mEnCounter >> 8)];
        ++mEnCounter;
    }
}

void
TqCipher_SSE2 :: decrypt(uint8_t* aBuf, size_t aLen)
{
    assert(aBuf != nullptr);
    assert(aLen > 0);

    uint8_t* key1 = mUsingAltKey ? mAltKey : mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2) + (sizeof(__m128i) - 1);

    uint8_t tmp[sizeof(__m128i)];
    __m128i* buf = (__m128i*)aBuf;
    __m128i x, y, z, w;

    z = _mm_set1_epi8(0xABU);
    for (size_t i = 0, count = aLen / sizeof(__m128i); i < count; ++i)
    {
        x = _mm_loadu_si128((__m128i*)&key1[(uint8_t)mDeCounter]);
        if (0x100 - mDeCounter % 0x100 >= sizeof(__m128i))
            y = _mm_set1_epi8(key2[(uint8_t)(mDeCounter >> 8)]);
        else
        {
            size_t n = 0x100 - mDeCounter % 0x100;
            memset(tmp, key2[(uint8_t)(mDeCounter >> 8)], n);
            memset(&tmp[n], key2[(uint8_t)(mDeCounter >> 8) + 1], sizeof(__m128i) - n);
            y = _mm_loadu_si128((__m128i*)tmp);
        }

        w = _mm_loadu_si128(&buf[i]);

        w = _mm_xor_si128(w, z);
        w = _mm_or_si128(_mm_slli_epi8(w, 4), _mm_srli_epi8(w, 4));
        w = _mm_xor_si128(_mm_xor_si128(w, x), y);

        _mm_storeu_si128(&buf[i], w);

        mDeCounter += sizeof(__m128i);
    }

    for (size_t i = aLen - (aLen % sizeof(__m128i)); i < aLen; ++i)
    {
        aBuf[i] ^= UINT8_C(0xAB);
        aBuf[i] = (uint8_t)(aBuf[i] << 4 | aBuf[i] >> 4);
        aBuf[i] ^= key1[(uint8_t)mDeCounter];
        aBuf[i] ^= key2[(uint8_t)(mDeCounter >> 8)];
        ++mDeCounter;
    }
}