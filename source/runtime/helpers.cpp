#include "memory.hpp"
#include <print>

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

        Memory* __remill_function_return(State&, addr_t, Memory* memory)
        {
            return memory;
        }

        Memory* __remill_async_hyper_call(State&, addr_t address, Memory*)
        {
            std::println("Async hyper call to 0x{:x}", address);
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

        float32_t __analysis_remill_read_memory_f32(Memory* m, addr_t a)
        {
            return read_memory<float32_t>(m, a);
        }

        float64_t __remill_read_memory_f64(Memory* m, addr_t a)
        {
            return read_memory<float64_t>(m, a);
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
    }
}
