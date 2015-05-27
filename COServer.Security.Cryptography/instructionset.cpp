/*
 * *** COServer.Security.Cryptography - Closed Source ***
 * Copyright (C) 2014 - 2015 Jean-Philippe Boivin
 *
 * Please read the WARNING, DISCLAIMER and PATENTS
 * sections in the LICENSE file.
 */

#include "instructionset.h"

#pragma unmanaged

const InstructionSet::InstructionSet_Internal* InstructionSet::sInstructions = new InstructionSet::InstructionSet_Internal();

InstructionSet::InstructionSet_Internal :: InstructionSet_Internal()
    : mIsIntel(false), mIsAMD(false)
{
    std::vector<std::array<int, 4>> data_;
    std::vector<std::array<int, 4>> extdata_;
    std::array<int, 4> cpui;

    // Calling __cpuid with 0x0 as the function_id argument
    // gets the number of the highest valid function ID.
    __cpuid(cpui.data(), 0);
    int ids = cpui[0];

    for (int i = 0; i <= ids; ++i)
    {
        __cpuidex(cpui.data(), i, 0);
        data_.push_back(cpui);
    }

    // Capture vendor string
    char vendor[0x20];
    memset(vendor, 0, sizeof(vendor));
    *reinterpret_cast<int*>(vendor) = data_[0][1];
    *reinterpret_cast<int*>(vendor + 4) = data_[0][3];
    *reinterpret_cast<int*>(vendor + 8) = data_[0][2];
    mVendor = vendor;

    mIsIntel = (mVendor == "GenuineIntel");
    mIsAMD = (mVendor == "AuthenticAMD");

    // load bitset with flags for function 0x00000001
    if (ids >= 1)
    {
        f_1_ECX_ = data_[1][2];
        f_1_EDX_ = data_[1][3];
    }

    // load bitset with flags for function 0x00000007
    if (ids >= 7)
    {
        f_7_EBX_ = data_[7][1];
        f_7_ECX_ = data_[7][2];
    }

    // Calling __cpuid with 0x80000000 as the function_id argument
    // gets the number of the highest valid extended ID.
    __cpuid(cpui.data(), 0x80000000);
    int extIds = cpui[0];

    for (int i = 0x80000000; i <= extIds; ++i)
    {
        __cpuidex(cpui.data(), i, 0);
        extdata_.push_back(cpui);
    }

    // load bitset with flags for function 0x80000001
    if (extIds >= 0x80000001)
    {
        f_81_ECX_ = extdata_[1][2];
        f_81_EDX_ = extdata_[1][3];
    }

    // Interpret CPU brand string if reported
    if (extIds >= 0x80000004)
    {
        char brand[0x40];
        memset(brand, 0, sizeof(brand));

        memcpy(brand, extdata_[2].data(), sizeof(cpui));
        memcpy(brand + 16, extdata_[3].data(), sizeof(cpui));
        memcpy(brand + 32, extdata_[4].data(), sizeof(cpui));
        mBrand = brand;
    }
}

#pragma managed