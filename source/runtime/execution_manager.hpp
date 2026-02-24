#pragma once
#include "memory.hpp"

#include <cstddef>
#include <cstring>
#include <map>
#include <span>
#include <array>
#include <stdexcept>
#include <mutex>
#include <shared_mutex>

namespace levo::runtime
{
    inline size_t align_down(const size_t value, const size_t alignment)
    {
        return value & ~(alignment - 1);
    }

    inline size_t align_up(const size_t value, const size_t alignment)
    {
        return align_down(value + alignment - 1, alignment);
    }

    class execution_manager : public Memory
    {
      public:
        bool read(addr_t address, void* buffer, size_t size) override
        {
            std::shared_lock lock(memory_mutex_);

            const auto memory = get_memory(address, size);
            if (memory.size() < size)
            {
                return false;
            }

            memcpy(buffer, memory.data(), size);
            return true;
        }

        bool write(addr_t address, const void* buffer, size_t size) override
        {
            // Maybe we should use a unique lock here?
            std::shared_lock lock(memory_mutex_);

            const auto memory = get_memory(address, size);
            if (memory.size() < size)
            {
                return false;
            }

            memcpy(memory.data(), buffer, size);
            return true;
        }

        bool compare_exchange(addr_t address, void* expected, void* desired, size_t size) override
        {
            std::unique_lock lock(memory_mutex_);

            const auto memory = get_memory(address, size);
            if (memory.size() < size)
            {
                return false;
            }

            const auto matches_expected = memcmp(memory.data(), expected, size) == 0;

            if (matches_expected)
            {
                memcpy(memory.data(), desired, size);
            }
            else
            {
                memcpy(expected, memory.data(), size);
            }

            return true;
        }

        void map(addr_t address, std::vector<uint8_t> data)
        {
            std::unique_lock lock(memory_mutex_);
            memory_[address] = std::move(data);
        }

        void map(addr_t address, size_t size)
        {
            map(address, std::vector<uint8_t>(size, 0));
        }

        addr_t map_somewhere(size_t size)
        {
            std::unique_lock lock(memory_mutex_);

            const auto address = find_free_address(size);
            memory_[address] = std::vector<uint8_t>(size, 0);
            return address;
        }

        void unmap(addr_t address)
        {
            std::unique_lock lock(memory_mutex_);

            const auto it = memory_.find(address);
            if (it != memory_.end())
            {
                memory_.erase(it);
            }
        }

        system_function* get_function(addr_t address)
        {
            std::shared_lock lock(function_mutex_);

            auto it = functions_.find(address);
            if (it != functions_.end())
            {
                return it->second;
            }
            return nullptr;
        }

        void add_function(addr_t address, system_function* function)
        {
            std::unique_lock lock(function_mutex_);
            functions_[address] = function;
        }

        Memory* run(State& state) override
        {
            const auto function = get_function(state.gpr.rip.aword);
            if (!function)
            {
                std::array<char, 100> buffer{};
                snprintf(buffer.data(), buffer.size() - 1, "Function not found at 0x%" ADDR_FORMAT, state.gpr.rip.aword);

                throw std::runtime_error(buffer.data());
            }

            //__attribute__((musttail))
            return function(state, state.gpr.rip.aword, this);
        }

      private:
        std::shared_mutex memory_mutex_;
        std::shared_mutex function_mutex_;
        std::map<addr_t, system_function*> functions_;
        std::map<addr_t, std::vector<uint8_t>> memory_;

        addr_t find_free_address(const size_t size) const
        {
            constexpr addr_t allocation_granularity = 0x10000;
            addr_t last_end = allocation_granularity;

            for (const auto& [address, data] : memory_)
            {
                if (address >= (last_end + size))
                {
                    return last_end;
                }

                last_end = align_up(address + data.size(), allocation_granularity);
            }

            return last_end;
        }

        std::span<uint8_t> get_memory(addr_t address, size_t size = 1)
        {
            auto it = memory_.upper_bound(address);
            if (it == memory_.begin())
            {
                return {};
            }

            --it;

            if (address < it->first && (address + size) > it->second.size())
            {
                return {};
            }

            const auto offset = address - it->first;
            return {it->second.data() + offset, it->second.size() - offset};
        }
    };
}
