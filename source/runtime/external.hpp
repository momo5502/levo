#pragma once

#include "system.hpp"

namespace levo::runtime
{
    struct DispatchEntry
    {
        uint64_t address;
        system_function* function;
    };

    extern "C"
    {
        extern const DispatchEntry dispatch_table[];
        extern const uint8_t binary_data[];
        extern const uint64_t binary_size;
        extern const uint64_t image_base;
    }
}
