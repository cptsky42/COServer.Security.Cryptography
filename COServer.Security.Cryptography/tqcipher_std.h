/*
 * *** COServer.Security.Cryptography - Closed Source ***
 * Copyright (C) 2014 - 2015 Jean-Philippe Boivin
 *
 * Please read the WARNING, DISCLAIMER and PATENTS
 * sections in the LICENSE file.
 */

#ifndef _TQ_CIPHER_NO_SIMD_H_
#define _TQ_CIPHER_NO_SIMD_H_

#include "tqcipher_base.h"
#include <stdint.h>

/**
 * TQ Digital's cipher used by the AccServer of the game Conquer Online.
 * It uses a 4096-bit key, based from two 32-bit integer, with two 16-bit
 * incremental counter. The cipher is barely a XOR cipher.
 *
 * The following implementation has a memory footprint of 1 KiO.
 */
class TqCipher_Std : public TqCipher_Base
{
public:
    /**
     * Create a new instance of the cipher where the IV and the key is
     * zero-filled.
     */
    TqCipher_Std();

    /* destructor */
    virtual ~TqCipher_Std() {  }

public:
    /**
     * Generate the base key based on the P & G integers which
     * are respectively two 32-bit integers.
     *
     * @param[in] aP  the P value of the cipher
     * @param[in] aG  the G value of the cipher
     */
    virtual void generateKey(uint32_t aP, uint32_t aG);

    /**
     * Generate an alternate key to use for the algorithm and reset
     * the encryption counter.
     *
     * @param[in] aA  the A value of the cipher (Token)
     * @param[in] aB  the B value of the cipher (AccountUID)
     */
    virtual void generateAltKey(int32_t aA, int32_t aB);

    /**
     * Encrypt n octet(s) with the cipher.
     *
     * @param[in,out] aBuf          the buffer that will be encrypted
     * @param[in]     aLen          the number of octets to encrypt
     */
    virtual void encrypt(uint8_t* aBuf, size_t aLen);

    /**
     * Decrypt n octet(s) with the cipher.
     *
     * @param[in,out] aBuf          the buffer that will be decrypted
     * @param[in]     aLen          the number of octets to decrypt
     */
    virtual void decrypt(uint8_t* aBuf, size_t aLen);

    /**
     * Reset the decrypt and the encrypt counters.
     */
    virtual void resetCounters() { mEnCounter = 0; mDeCounter = 0; }

private:
    uint16_t mEnCounter; //!< Internal encryption counter.
    uint16_t mDeCounter; //!< Internal decryption counter.

    uint8_t mKey[KEY_SIZE]; //!< Base key
    uint8_t mAltKey[KEY_SIZE]; //!< Alternative key
    bool mUsingAltKey; //!< Whether or not the alternate key must be used
};

#endif // _TQ_CIPHER_NO_SIMD_H_
