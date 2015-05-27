/*
 * *** COServer.Security.Cryptography - Closed Source ***
 * Copyright (C) 2015 Jean-Philippe Boivin
 *
 * Please read the WARNING, DISCLAIMER and PATENTS
 * sections in the LICENSE file.
 */

#include "tqcipher.h"
#include "tqcipher_avx2.h"
#include "tqcipher_sse2.h"
#include "tqcipher_std.h"
#include "instructionset.h"

using namespace COServer::Security::Cryptography;

System::String^
TqCipher :: GetImplInfo()
{
    if (InstructionSet::AVX2())
        return "TqCipher (AVX2)";
    else if (InstructionSet::SSE2())
        return "TqCipher (SSE2)";
    else
        return "TqCipher (Standard)";
}

TqCipher::ImplType
TqCipher :: GetImplType()
{
	if (InstructionSet::AVX2())
		return ImplType::AVX2;
	else if (InstructionSet::SSE2())
		return ImplType::SSE2;
	else
		return ImplType::Standard;
}

TqCipher :: TqCipher()
    : mCipher(nullptr)
{
	if (InstructionSet::AVX2())
		mCipher = new TqCipher_AVX2();
	else if (InstructionSet::SSE2())
		mCipher = new TqCipher_SSE2();
	else
        mCipher = new TqCipher_Std();

    mCipher->generateKey(TqCipher::P, TqCipher::G);
}

TqCipher :: TqCipher(TqCipher::ImplType aType)
	: mCipher(nullptr)
{
	switch (aType)
	{
	case ImplType::AVX2:
		{
			if (!InstructionSet::AVX2())
				throw gcnew System::NotSupportedException("AVX2 instruction set is not supported on the processor.");

			mCipher = new TqCipher_AVX2();
			break;
		}
		case ImplType::SSE2:
		{
			if (!InstructionSet::SSE2())
				throw gcnew System::NotSupportedException("SSE2 instruction set is not supported on the processor.");

			mCipher = new TqCipher_SSE2();
			break;
		}
		case ImplType::Standard:
		{
			mCipher = new TqCipher_Std();
			break;
		}
		default:
			throw gcnew System::NotImplementedException("The specified implementation is unknown.");
	}

	mCipher->generateKey(TqCipher::P, TqCipher::G);
}

TqCipher :: ~TqCipher()
{
    delete mCipher;
    mCipher = nullptr;
}

void
TqCipher :: GenerateAltKey(System::Int32 A, System::Int32 B)
{
    mCipher->generateAltKey(A, B);
}

void
TqCipher :: Encrypt(array<System::Byte>^% aBuf, int aLength)
{
	pin_ptr<uint8_t> buf = &aBuf[0];
    mCipher->encrypt(buf, aLength);
}

void
TqCipher :: Decrypt(array<System::Byte>^% aBuf, int aLength)
{
    pin_ptr<uint8_t> buf = &aBuf[0];
    mCipher->decrypt(buf, aLength);
}

void
TqCipher :: ResetCounters()
{
    mCipher->resetCounters();
}