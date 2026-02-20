#pragma once

#include "memory.hpp"
#include <stdexcept>

namespace levo::runtime
{
    enum class calling_convention
    {
        cdecl,
        stdcall,
    };

    namespace detail
    {
        inline void return_cdecl(Memory& memory, State& state)
        {
            state.gpr.rip.aword = *memory.read<addr_t>(state.gpr.rsp.aword);
            state.gpr.rsp.aword += sizeof(addr_t);
        }

        inline void return_stdcall(Memory& memory, State& state, uint32_t arg_count)
        {
            return_cdecl(memory, state);
            state.gpr.rsp.aword += sizeof(addr_t) * arg_count;
        }

        inline std::optional<addr_t> read_stack_value(Memory& memory, State& state, uint32_t arg_index)
        {
            return memory.read<addr_t>(state.gpr.rsp.aword + (sizeof(addr_t) * arg_index));
        }

        inline std::optional<addr_t> read_argument_win64(Memory& memory, State& state, uint32_t arg_index)
        {
            switch (arg_index)
            {
            case 0:
                return state.gpr.rcx.aword;
            case 1:
                return state.gpr.rdx.aword;
            case 2:
                return state.gpr.r8.aword;
            case 3:
                return state.gpr.r9.aword;
            default:
                return read_stack_value(memory, state, arg_index + 1);
            }
        }
    }

    inline Memory* return_function(Memory& memory, State& state, calling_convention cc, uint32_t arg_count)
    {
        if constexpr (ADDRESS_SIZE_BITS == 32)
        {
            switch (cc)
            {
            case calling_convention::cdecl:
                detail::return_cdecl(memory, state);
                break;
            case calling_convention::stdcall:
                detail::return_stdcall(memory, state, arg_count);
                break;
            default:
                throw std::runtime_error("Unsupported calling convention");
            }
        }
        else
        {
            detail::return_cdecl(memory, state);
        }

        return &memory;
    }

    inline std::optional<addr_t> read_argument(Memory& memory, State& state, calling_convention cc, uint32_t arg_index)
    {
        if constexpr (ADDRESS_SIZE_BITS == 64)
        {
            return detail::read_argument_win64(memory, state, arg_index);
        }

        switch (cc)
        {
        case calling_convention::cdecl:
        case calling_convention::stdcall:
            return detail::read_stack_value(memory, state, arg_index + 1);
        default:
            throw std::runtime_error("Unsupported calling convention");
        }
    }
}
