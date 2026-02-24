#pragma once

#include <cfenv>
#include <cfloat>
#include <cstdint>
#include <cinttypes>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-literal-operator"
#include "remill/Arch/X86/Runtime/State.h"
#pragma clang diagnostic pop

#if ADDRESS_SIZE_BITS == 32
using addr_t = uint32_t;
#define ADDR_FORMAT PRIx32
#define aword       dword
#else
using addr_t = uint64_t;
#define ADDR_FORMAT PRIx64
#define aword       qword
#endif

using system_function = Memory*(State& state, addr_t address, Memory* memory);
