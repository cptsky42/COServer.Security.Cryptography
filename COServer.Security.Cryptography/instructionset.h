/*
 * *** COServer.Security.Cryptography - Closed Source ***
 * Copyright (C) 2014 - 2015 Jean-Philippe Boivin
 *
 * Please read the WARNING, DISCLAIMER and PATENTS
 * sections in the LICENSE file.
 */

#ifndef _INSTRUCTION_SET_H_
#define _INSTRUCTION_SET_H_

#include <vector>
#include <bitset>
#include <array>
#include <string>
#include <intrin.h>

class InstructionSet
{
    class InstructionSet_Internal;

public:
    // getters
    static std::string getVendor() { return sInstructions->mVendor; }
    static std::string getBrand() { return sInstructions->mBrand; }

    static bool SSE3() { return sInstructions->f_1_ECX_[0]; }
    static bool PCLMULQDQ() { return sInstructions->f_1_ECX_[1]; }
    static bool MONITOR() { return sInstructions->f_1_ECX_[3]; }
    static bool SSSE3() { return sInstructions->f_1_ECX_[9]; }
    static bool FMA() { return sInstructions->f_1_ECX_[12]; }
    static bool CMPXCHG16B() { return sInstructions->f_1_ECX_[13]; }
    static bool SSE41() { return sInstructions->f_1_ECX_[19]; }
    static bool SSE42() { return sInstructions->f_1_ECX_[20]; }
    static bool MOVBE() { return sInstructions->f_1_ECX_[22]; }
    static bool POPCNT() { return sInstructions->f_1_ECX_[23]; }
    static bool AES() { return sInstructions->f_1_ECX_[25]; }
    static bool XSAVE() { return sInstructions->f_1_ECX_[26]; }
    static bool OSXSAVE() { return sInstructions->f_1_ECX_[27]; }
    static bool AVX() { return sInstructions->f_1_ECX_[28]; }
    static bool F16C() { return sInstructions->f_1_ECX_[29]; }
    static bool RDRAND() { return sInstructions->f_1_ECX_[30]; }

    static bool MSR() { return sInstructions->f_1_EDX_[5]; }
    static bool CX8() { return sInstructions->f_1_EDX_[8]; }
    static bool SEP() { return sInstructions->f_1_EDX_[11]; }
    static bool CMOV() { return sInstructions->f_1_EDX_[15]; }
    static bool CLFSH() { return sInstructions->f_1_EDX_[19]; }
    static bool MMX() { return sInstructions->f_1_EDX_[23]; }
    static bool FXSR() { return sInstructions->f_1_EDX_[24]; }
    static bool SSE() { return sInstructions->f_1_EDX_[25]; }
    static bool SSE2() { return sInstructions->f_1_EDX_[26]; }

    static bool FSGSBASE() { return sInstructions->f_7_EBX_[0]; }
    static bool BMI1() { return sInstructions->f_7_EBX_[3]; }
    static bool HLE() { return sInstructions->mIsIntel && sInstructions->f_7_EBX_[4]; }
    static bool AVX2() { return sInstructions->f_7_EBX_[5]; }
    static bool BMI2() { return sInstructions->f_7_EBX_[8]; }
    static bool ERMS() { return sInstructions->f_7_EBX_[9]; }
    static bool INVPCID() { return sInstructions->f_7_EBX_[10]; }
    static bool RTM() { return sInstructions->mIsIntel && sInstructions->f_7_EBX_[11]; }
    static bool AVX512F() { return sInstructions->f_7_EBX_[16]; }
    static bool RDSEED() { return sInstructions->f_7_EBX_[18]; }
    static bool ADX() { return sInstructions->f_7_EBX_[19]; }
    static bool AVX512PF() { return sInstructions->f_7_EBX_[26]; }
    static bool AVX512ER() { return sInstructions->f_7_EBX_[27]; }
    static bool AVX512CD() { return sInstructions->f_7_EBX_[28]; }
    static bool SHA() { return sInstructions->f_7_EBX_[29]; }

    static bool PREFETCHWT1() { return sInstructions->f_7_ECX_[0]; }

    static bool LAHF() { return sInstructions->f_81_ECX_[0]; }
    static bool LZCNT() { return sInstructions->mIsIntel && sInstructions->f_81_ECX_[5]; }
    static bool ABM() { return sInstructions->mIsAMD && sInstructions->f_81_ECX_[5]; }
    static bool SSE4a() { return sInstructions->mIsAMD && sInstructions->f_81_ECX_[6]; }
    static bool XOP() { return sInstructions->mIsAMD && sInstructions->f_81_ECX_[11]; }
    static bool TBM() { return sInstructions->mIsAMD && sInstructions->f_81_ECX_[21]; }

    static bool SYSCALL() { return sInstructions->mIsIntel && sInstructions->f_81_EDX_[11]; }
    static bool MMXEXT() { return sInstructions->mIsAMD && sInstructions->f_81_EDX_[22]; }
    static bool RDTSCP() { return sInstructions->mIsIntel && sInstructions->f_81_EDX_[27]; }
    static bool _3DNOWEXT() { return sInstructions->mIsAMD && sInstructions->f_81_EDX_[30]; }
    static bool _3DNOW() { return sInstructions->mIsAMD && sInstructions->f_81_EDX_[31]; }

private:
    static const InstructionSet_Internal* sInstructions;

    class InstructionSet_Internal
    {
        friend class InstructionSet;

    public:
        InstructionSet_Internal();

    private:
        std::string mVendor;
        std::string mBrand;
        bool mIsIntel;
        bool mIsAMD;
        std::bitset<32> f_1_ECX_;
        std::bitset<32> f_1_EDX_;
        std::bitset<32> f_7_EBX_;
        std::bitset<32> f_7_ECX_;
        std::bitset<32> f_81_ECX_;
        std::bitset<32> f_81_EDX_;
    };
};

#endif // _INSTRUCTION_SET_H_