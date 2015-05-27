/*
 * *** COServer.Security.Cryptography - Closed Source ***
 * Copyright (C) 2014 - 2015 Jean-Philippe Boivin
 *
 * Please read the WARNING, DISCLAIMER and PATENTS
 * sections in the LICENSE file.
 */

#include "tqcipher_std.h"
#include <string.h> // memset
#include <assert.h>

TqCipher_Std :: TqCipher_Std()
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
TqCipher_Std :: generateKey(uint32_t aP, uint32_t aG)
{
    uint8_t* p = (uint8_t*)&aP;
    uint8_t* g = (uint8_t*)&aG;

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2);

    for (size_t i = 0, len = (KEY_SIZE  / 2); i < len; ++i)
    {
        key1[i] = p[0];
        key2[i] = g[0];
        p[0] = (uint8_t)((p[1] + (uint8_t)(p[0] * p[2])) * p[0] + p[3]);
        g[0] = (uint8_t)((g[1] - (uint8_t)(g[0] * g[2])) * g[0] + g[3]);
    }
}
#pragma optimize( "", on ) 

void
TqCipher_Std :: generateAltKey(int32_t aA, int32_t aB)
{
    uint32_t x = (uint32_t)(((aA + aB) ^ 0x4321) ^ aA);
    uint32_t y = x * x;

    uint8_t* tmpKey1 = (uint8_t*)&x;
    uint8_t* tmpKey2 = (uint8_t*)&y;

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2);
    uint8_t* altKey1 = mAltKey;
    uint8_t* altKey2 = altKey1 + (KEY_SIZE  / 2);

    for (size_t i = 0, len = (KEY_SIZE / 2); i < len; ++i)
    {
        altKey1[i] = (uint8_t)(key1[i] ^ tmpKey1[(i % sizeof(x))]);
        altKey2[i] = (uint8_t)(key2[i] ^ tmpKey2[(i % sizeof(y))]);
    }

    mUsingAltKey = true;
    mEnCounter = 0;
}

void
TqCipher_Std :: encrypt(uint8_t* aBuf, size_t aLen)
{
    assert(aBuf != nullptr);
    assert(aLen > 0);

    uint8_t* key1 = mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2);

    for (size_t i = 0; i < aLen; ++i)
    {
        aBuf[i] ^= UINT8_C(0xAB);
        aBuf[i] = (uint8_t)(aBuf[i] << 4 | aBuf[i] >> 4);
        aBuf[i] ^= key1[(uint8_t)mEnCounter];
        aBuf[i] ^= key2[(uint8_t)(mEnCounter >> 8)];
        ++mEnCounter;
    }
}

#include <stdio.h>

void
TqCipher_Std :: decrypt(uint8_t* aBuf, size_t aLen)
{
    assert(aBuf != nullptr);
    assert(aLen > 0);

    uint8_t* key1 = mUsingAltKey ? mAltKey : mKey;
    uint8_t* key2 = key1 + (KEY_SIZE  / 2);

    for (size_t i = 0; i < aLen; ++i)
    {
        aBuf[i] ^= UINT8_C(0xAB);
        aBuf[i] = (uint8_t)(aBuf[i] << 4 | aBuf[i] >> 4);
        aBuf[i] ^= key1[(uint8_t)mDeCounter];
        aBuf[i] ^= key2[(uint8_t)(mDeCounter >> 8)];
        ++mDeCounter;
    }
}