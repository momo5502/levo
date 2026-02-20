#pragma once
#include "memory.hpp"

#include <map>
#include <span>
#include <format>
#include <stdexcept>

namespace levo::runtime
{
    class execution_manager : public Memory
    {
      public:
        bool read(addr_t address, void* buffer, size_t size) override
        {
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
            const auto memory = get_memory(address, size);
            if (memory.size() < size)
            {
                return false;
            }

            memcpy(memory.data(), buffer, size);
            return true;
        }

        void map(addr_t address, std::vector<uint8_t> data)
        {
            mapped_memory_[address] = std::move(data);
        }

        void map(addr_t address, size_t size)
        {
            map(address, std::vector<uint8_t>(size, 0));
        }

        void unmap(addr_t address)
        {
            const auto it = mapped_memory_.find(address);
            if (it != mapped_memory_.end())
            {
                mapped_memory_.erase(it);
            }
        }

        system_function* get_function(addr_t address) const
        {
            auto it = functions_.find(address);
            if (it != functions_.end())
            {
                return it->second;
            }
            return nullptr;
        }

        void add_function(addr_t address, system_function* function)
        {
            functions_[address] = function;
        }

        Memory* run(State& state) override
        {
            const auto function = get_function(state.gpr.rip.aword);
            if (!function)
            {
                throw std::runtime_error(std::format("Function not found at 0x{:x}", state.gpr.rip.aword));
            }

            //__attribute__((musttail))
            return function(state, state.gpr.rip.aword, this);
        }

      private:
        // TODO: Lock
        std::map<addr_t, system_function*> functions_;
        std::map<addr_t, std::vector<uint8_t>> mapped_memory_;

        std::span<uint8_t> get_memory(addr_t address, size_t size = 1)
        {
            auto it = mapped_memory_.upper_bound(address);
            if (it == mapped_memory_.begin())
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
