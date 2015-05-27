/*
 * *** COServer.Security.Cryptography - Closed Source ***
 * Copyright (C) 2015 Jean-Philippe Boivin
 *
 * Please read the WARNING, DISCLAIMER and PATENTS
 * sections in the LICENSE file.
 */

#ifndef _TQ_CIPHER_H_
#define _TQ_CIPHER_H_

class TqCipher_Base;

namespace COServer
{
	namespace Security
	{
		namespace Cryptography
		{
			/// <summary>
			/// TQ Digital's Asymmetric Cipher (used on the servers).
			/// </summary>
			public ref class TqCipher
			{
			public:
				/// <summary>
				/// Integer constant used to generate the initial key.
                ///
                /// This constant can be changed if the server does not use the original keys.
				/// </summary>
				static System::UInt32 P = 0x13FA0F9D;
				/// <summary>
				/// Integer constant used to generate the initial key.
                ///
                /// This constant can be changed if the server does not use the original keys.
				/// </summary>
				static System::UInt32 G = 0x6D5C7962;

			public:
                /// <summary>
                /// Type of the implementation of the cipher.
                /// </summary>
				enum class ImplType
				{
                    /// <summary>
                    /// Implementation based on standard arithmetic.
                    /// </summary>
					Standard,
                    /// <summary>
                    /// Implementation based on vectorized arithmetic, using the SSE and SSE2 instruction sets.
                    /// </summary>
					SSE2,
                    /// <summary>
                    /// Implementation based on vectorized arithmetic, using the AVX and AVX2 instruction sets.
                    /// </summary>
					AVX2
				};

            public:
                /// <summary>
                /// Get the name of the type of the implementation that will be used by default.
                /// </summary>
                /// <returns></returns>
                static System::String^ GetImplInfo();

                /// <summary>
                /// Get the type of the implementation that will be used by default.
                /// </summary>
                /// <returns></returns>
				static ImplType GetImplType();

			public:
                /// <summary>
                /// Create a new cipher instance. The key will be generated using the P and G constants.
                /// </summary>
                TqCipher();

				/// <summary>
				/// Create a new cipher instance. The key will be generated using the P and G constants.
				///
				/// It will try to use the specified implementation.
				/// </summary>
                /// <param name="aType">The type of the implementation to use for this instance.</param>
				TqCipher(ImplType aType);

                /* destructor */
                ~TqCipher();

                /// <summary>
                /// Generates an alternate key to use for the algorithm and reset the encryption counter.
                /// 
                /// In Conquer Online: A = Token, B = AccountUID
                /// </summary>
                /// <param name="A">The first 32 bits seed to use to generate the alternate key.</param>
                /// <param name="B">The second 32 bits seed to use to generate the alternate key.</param>
                void GenerateAltKey(System::Int32 A, System::Int32 B);

                /// <summary>
                /// Encrypts data with the algorithm.
                /// </summary>
                /// <param name="aBuf">A reference to the buffer to encrypt using the cipher.</param>
                /// <param name="aLength">The number of bytes of the buffer to encrypt using the cipher.</param>
				void Encrypt(array<System::Byte>^% aBuf, int aLength);

                /// <summary>
                /// Decrypts data with the algorithm.
                /// </summary>
                /// <param name="aBuf">A reference to the buffer to decrypt using the cipher.</param>
                /// <param name="aLength">The number of bytes of the buffer to decrypt using the cipher.</param>
                void Decrypt(array<System::Byte>^% aBuf, int aLength);

                /// <summary>
                /// Resets the decryption and encryption counters.
                /// </summary>
                void ResetCounters();

            private:
                /// <summary>
                /// Native cipher object.
                /// </summary>
                TqCipher_Base* mCipher;
			};
		}
	}
}

#endif // _TQ_CIPHER_H_