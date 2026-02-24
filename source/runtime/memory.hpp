#pragma once
#include "system.hpp"

#include <optional>
#include <vector>

struct Memory
{
    virtual bool read(addr_t address, void* buffer, size_t size) = 0;
    virtual bool write(addr_t address, const void* buffer, size_t size) = 0;
    virtual bool compare_exchange(addr_t address, void* expected, void* desired, size_t size) = 0;
    virtual Memory* run(State& state) = 0;

    template <typename T>
    std::optional<T> read(addr_t address)
    {
        T value{};
        if (read(address, &value, sizeof(value)))
        {
            return value;
        }

        return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> read(addr_t address, size_t size)
    {
        std::vector<uint8_t> value(size);
        if (read(address, value.data(), size))
        {
            return value;
        }
        return std::nullopt;
    }

    template <typename T>
    bool write(addr_t address, const T& value)
    {
        return write(address, &value, sizeof(value));
    }
};
