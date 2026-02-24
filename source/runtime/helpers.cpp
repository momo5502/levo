#include "memory.hpp"
#include <cstdio>
#include <cfenv>

namespace levo::runtime
{
    namespace
    {
        template <typename T>
        void write_memory(Memory* m, addr_t address, const T& value)
        {
            m->write(address, &value, sizeof(value));
        }

        template <typename T>
        T read_memory(Memory* m, uint64_t address)
        {
            T value{};
            m->read(address, &value, sizeof(value));
            return value;
        }

        template <typename T>
        bool compare_exchange_memory(Memory* m, addr_t address, T& expected, T desired)
        {
            return m->compare_exchange(address, &expected, &desired, sizeof(T));
        }

        int MapFpuExceptToFe(int32_t guest_except)
        {
            int host_except = 0;
            if (guest_except & kFPUExceptionInvalid)
            {
                host_except |= FE_INVALID;
            }
            if (guest_except & kFPUExceptionDivByZero)
            {
                host_except |= FE_DIVBYZERO;
            }
            if (guest_except & kFPUExceptionOverflow)
            {
                host_except |= FE_OVERFLOW;
            }
            if (guest_except & kFPUExceptionUnderflow)
            {
                host_except |= FE_UNDERFLOW;
            }
            if (guest_except & kFPUExceptionPrecision)
            {
                host_except |= FE_INEXACT;
            }
            // NOTE: denormal exception is not available on all architectures
#ifdef FE_DENORMALOPERAND
            if (guest_except & kFPUExceptionDenormal)
            {
                host_except |= FE_DENORMALOPERAND;
            }
#endif // FE_DENORMALOPERAND
#ifdef FE_DENORMAL
            if (guest_except & kFPUExceptionDenormal)
            {
                host_except |= FE_DENORMAL;
            }
#endif
            return host_except;
        }

        int MapFeToFpuExcept(int host_except)
        {
            int guest_except = 0;
            if (host_except & FE_INVALID)
            {
                guest_except |= kFPUExceptionInvalid;
            }
            if (host_except & FE_DIVBYZERO)
            {
                guest_except |= kFPUExceptionDivByZero;
            }
            if (host_except & FE_OVERFLOW)
            {
                guest_except |= kFPUExceptionOverflow;
            }
            if (host_except & FE_UNDERFLOW)
            {
                guest_except |= kFPUExceptionUnderflow;
            }
            if (host_except & FE_INEXACT)
            {
                guest_except |= kFPUExceptionPrecision;
            }
            // NOTE: denormal exception is not available on all architectures
#ifdef FE_DENORMALOPERAND
            if (host_except & FE_DENORMALOPERAND)
            {
                guest_except |= kFPUExceptionDenormal;
            }
#endif // FE_DENORMALOPERAND
#ifdef FE_DENORMAL
            if (host_except & FE_DENORMAL)
            {
                guest_except |= kFPUExceptionDenormal;
            }
#endif
            return guest_except;
        }

        int MapFpuRoundToFe(int32_t guest_round)
        {
            switch (guest_round)
            {
            case kFPURoundToNearestEven:
                return FE_TONEAREST;
            case kFPURoundUpInf:
                return FE_UPWARD;
            case kFPURoundDownNegInf:
                return FE_DOWNWARD;
            case kFPURoundToZero:
                return FE_TOWARDZERO;
            default:
                return FE_TONEAREST;
            }
        }

        int MapFeToFpuRound(int host_round)
        {
            switch (host_round)
            {
            case FE_TONEAREST:
                return kFPURoundToNearestEven;
            case FE_UPWARD:
                return kFPURoundUpInf;
            case FE_DOWNWARD:
                return kFPURoundDownNegInf;
            case FE_TOWARDZERO:
                return kFPURoundToZero;
            default:
                return kFPURoundToNearestEven;
            }
        }

    }

    extern "C"
    {
        Memory* __remill_missing_block(State&, addr_t, Memory* memory)
        {
            return memory;
        }

        Memory* __remill_function_call(State& state, addr_t address, Memory* memory)
        {
            state.gpr.rip.aword = address;
            // __attribute__((musttail))
            return memory->run(state);
        }

        Memory* __remill_jump(State& state, addr_t address, Memory* memory)
        {
            state.gpr.rip.aword = address;
            // __attribute__((musttail))
            return memory->run(state);
        }

        Memory* __remill_function_return(State&, addr_t, Memory* memory)
        {
            return memory;
        }

        Memory* __remill_async_hyper_call(State&, addr_t address, Memory*)
        {
            printf("Async hyper call to 0x%" ADDR_FORMAT "\n", address);
            abort();
        }

        uint8_t __remill_read_memory_8(Memory* m, addr_t a)
        {
            return read_memory<uint8_t>(m, a);
        }

        uint16_t __remill_read_memory_16(Memory* m, addr_t a)
        {
            return read_memory<uint16_t>(m, a);
        }

        uint32_t __remill_read_memory_32(Memory* m, addr_t a)
        {
            return read_memory<uint32_t>(m, a);
        }

        uint64_t __remill_read_memory_64(Memory* m, addr_t a)
        {
            return read_memory<uint64_t>(m, a);
        }

        float32_t __remill_read_memory_f32(Memory* m, addr_t a)
        {
            return read_memory<float32_t>(m, a);
        }

        float64_t __remill_read_memory_f64(Memory* m, addr_t a)
        {
            return read_memory<float64_t>(m, a);
        }

        Memory* __remill_read_memory_f80(Memory* m, addr_t a, float80_t& v)
        {
            v = read_memory<float80_t>(m, a);
            return m;
        }

        Memory* __remill_write_memory_8(Memory* m, addr_t a, uint8_t v)
        {
            write_memory(m, a, v);
            return m;
        }

        Memory* __remill_write_memory_16(Memory* m, addr_t a, uint16_t v)
        {
            write_memory(m, a, v);
            return m;
        }

        Memory* __remill_write_memory_32(Memory* m, addr_t a, uint32_t v)
        {
            write_memory(m, a, v);
            return m;
        }

        Memory* __remill_write_memory_64(Memory* m, addr_t a, uint64_t v)
        {
            write_memory(m, a, v);
            return m;
        }

        Memory* __remill_write_memory_f32(Memory* m, addr_t a, float32_t v)
        {
            write_memory(m, a, v);
            return m;
        }

        Memory* __remill_write_memory_f64(Memory* m, addr_t a, float64_t v)
        {
            write_memory(m, a, v);
            return m;
        }

        NEVER_INLINE Memory* __remill_write_memory_f80(Memory* m, addr_t a, const float80_t& v)
        {
            write_memory(m, a, v);
            return m;
        }

        Memory* __remill_compare_exchange_memory_8(Memory* memory, addr_t addr, uint8_t& expected, uint8_t desired)
        {
            compare_exchange_memory(memory, addr, expected, desired);
            return memory;
        }

        Memory* __remill_compare_exchange_memory_16(Memory* memory, addr_t addr, uint16_t& expected, uint16_t desired)
        {
            compare_exchange_memory(memory, addr, expected, desired);
            return memory;
        }

        Memory* __remill_compare_exchange_memory_32(Memory* memory, addr_t addr, uint32_t& expected, uint32_t desired)
        {
            compare_exchange_memory(memory, addr, expected, desired);
            return memory;
        }

        Memory* __remill_compare_exchange_memory_64(Memory* memory, addr_t addr, uint64_t& expected, uint64_t desired)
        {
            compare_exchange_memory(memory, addr, expected, desired);
            return memory;
        }

        bool __remill_flag_computation_zero(bool result, ...)
        {
            return result;
        }

        bool __remill_flag_computation_sign(bool result, ...)
        {
            return result;
        }

        bool __remill_flag_computation_overflow(bool result, ...)
        {
            return result;
        }

        bool __remill_flag_computation_carry(bool result, ...)
        {
            return result;
        }

        bool __remill_compare_sle(bool result)
        {
            return result;
        }

        bool __remill_compare_slt(bool result)
        {
            return result;
        }

        bool __remill_compare_sge(bool result)
        {
            return result;
        }

        bool __remill_compare_sgt(bool result)
        {
            return result;
        }

        bool __remill_compare_ule(bool result)
        {
            return result;
        }

        bool __remill_compare_ult(bool result)
        {
            return result;
        }

        bool __remill_compare_ugt(bool result)
        {
            return result;
        }

        bool __remill_compare_uge(bool result)
        {
            return result;
        }

        bool __remill_compare_eq(bool result)
        {
            return result;
        }

        bool __remill_compare_neq(bool result)
        {
            return result;
        }

        uint8_t __remill_undefined_8()
        {
            return 0;
        }

        uint16_t __remill_undefined_16()
        {
            return 0;
        }

        uint32_t __remill_undefined_32()
        {
            return 0;
        }

        uint64_t __remill_undefined_64()
        {
            return 0;
        }

        Memory* __remill_atomic_begin(Memory* memory)
        {
            return memory;
        }

        Memory* __remill_atomic_end(Memory* memory)
        {
            return memory;
        }

        Memory* __remill_error(State&, addr_t address, Memory* memory)
        {
            printf("Error at 0x%" ADDR_FORMAT "\n", address);
            abort();
            return memory;
        }

        int32_t __remill_fpu_exception_test(int32_t read_mask)
        {
            int host_mask = MapFpuExceptToFe(read_mask);
            int host_result = std::fetestexcept(host_mask);
            return MapFeToFpuExcept(host_result);
        }

        void __remill_fpu_exception_clear(int32_t clear_mask)
        {
            int host_mask = MapFpuExceptToFe(clear_mask);
            std::feclearexcept(host_mask);
        }

        void __remill_fpu_exception_raise(int32_t except_mask)
        {
            int host_mask = MapFpuExceptToFe(except_mask);
            std::feraiseexcept(host_mask);
        }

        void __remill_fpu_set_rounding(int32_t round_mode)
        {
            int host_mode = MapFpuRoundToFe(round_mode);
            std::fesetround(host_mode);
        }

        int32_t __remill_fpu_get_rounding()
        {
            int host_mode = std::fegetround();
            return MapFeToFpuRound(host_mode);
        }
    }
}
