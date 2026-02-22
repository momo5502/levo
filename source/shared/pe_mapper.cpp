#include "pe_mapper.hpp"

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>
#include <type_traits>

namespace levo
{
    namespace
    {
        void grow_to_size(std::vector<uint8_t>& out, size_t size)
        {
            if (out.size() < size)
            {
                out.resize(size);
            }
        }

        // Returns a string_view over a null-terminated ASCII string at base + rva, or empty if invalid.
        std::string_view string_at_rva(std::span<const uint8_t> image, uint32_t rva)
        {
            if (rva >= image.size())
            {
                return {};
            }
            const char* start = reinterpret_cast<const char*>(image.data() + rva);
            const char* end = reinterpret_cast<const char*>(image.data() + image.size());
            const char* p = start;
            while (p < end && *p != '\0')
            {
                ++p;
            }

            return {start, static_cast<size_t>(p - start)};
        }

        // Maps PE sections and optionally resolves imports. OptionalHeaderT selects 32 vs 64 (IAT entry size).
        template <typename OptionalHeaderT>
        std::vector<uint8_t> map_pe_impl(std::span<const uint8_t> data, const pe_file_header& file_header, size_t section_table_offset,
                                         const pe_import_resolver_t& resolver)
        {
            constexpr size_t section_header_size = sizeof(pe_section_header);
            const size_t num_sections = file_header.number_of_sections;

            if (section_table_offset + (num_sections * section_header_size) > data.size())
            {
                return {};
            }

            std::vector<uint8_t> mapped_data;
            std::optional<size_t> first_section_file_offset;

            for (size_t i = 0; i < num_sections; ++i)
            {
                const size_t off = section_table_offset + (i * section_header_size);
                const auto* sh = reinterpret_cast<const pe_section_header*>(data.data() + off);

                const uint32_t virtual_address = sh->virtual_address;
                const uint32_t virtual_size = sh->virtual_size;
                const uint32_t size_of_raw_data = sh->size_of_raw_data;
                const uint32_t pointer_to_raw = sh->pointer_to_raw_data;

                if (size_of_raw_data > 0 && (pointer_to_raw + size_of_raw_data > data.size() || pointer_to_raw > data.size()))
                {
                    continue;
                }

                if (!first_section_file_offset.has_value() || pointer_to_raw < *first_section_file_offset)
                {
                    first_section_file_offset = pointer_to_raw;
                }

                grow_to_size(mapped_data, static_cast<size_t>(virtual_address) + virtual_size);
                const size_t copy_size = std::min(static_cast<size_t>(size_of_raw_data), static_cast<size_t>(virtual_size));
                if (copy_size > 0 && pointer_to_raw <= data.size() - copy_size)
                {
                    std::memcpy(mapped_data.data() + virtual_address, data.data() + pointer_to_raw, copy_size);
                }
            }

            // Copy headers (everything up to the first section's raw data).
            if (first_section_file_offset.has_value() && *first_section_file_offset > 0)
            {
                grow_to_size(mapped_data, *first_section_file_offset);
                std::memcpy(mapped_data.data(), data.data(), *first_section_file_offset);
            }

            // Resolve imports and fill IAT if resolver is provided.
            constexpr bool is_64 = std::is_same_v<OptionalHeaderT, pe_optional_header_64>;
            constexpr size_t iat_entry_size = is_64 ? 8u : 4u;

            if (resolver && mapped_data.size() >= sizeof(pe_dos_header))
            {
                const uint32_t e_lfanew = reinterpret_cast<const pe_dos_header*>(mapped_data.data())->e_lfanew;
                const size_t optional_header_offset = e_lfanew + 4u + sizeof(pe_file_header);
                if (optional_header_offset + sizeof(OptionalHeaderT) <= mapped_data.size())
                {
                    const auto* opt = reinterpret_cast<const OptionalHeaderT*>(mapped_data.data() + optional_header_offset);
                    const uint32_t import_rva = opt->data_directory[pe::directory_entry_import].virtual_address;
                    if (import_rva != 0)
                    {
                        std::span<const uint8_t> image(mapped_data.data(), mapped_data.size());
                        const auto* desc = reinterpret_cast<const pe_import_descriptor*>(mapped_data.data() + import_rva);

                        while (desc->name != 0)
                        {
                            const auto desc_offset = reinterpret_cast<const uint8_t*>(desc) - mapped_data.data();
                            if (desc_offset + sizeof(pe_import_descriptor) > mapped_data.size())
                            {
                                break;
                            }
                            std::string_view dll_name = string_at_rva(image, desc->name);
                            uint32_t ilt_rva = desc->original_first_thunk != 0 ? desc->original_first_thunk : desc->first_thunk;
                            uint32_t iat_rva = desc->first_thunk;

                            for (size_t idx = 0;; ++idx)
                            {
                                const size_t ilt_off = ilt_rva + (idx * iat_entry_size);
                                const size_t iat_off = iat_rva + (idx * iat_entry_size);
                                if (ilt_off + iat_entry_size > mapped_data.size() || iat_off + iat_entry_size > mapped_data.size())
                                {
                                    break;
                                }

                                uint64_t entry = 0;
                                if constexpr (is_64)
                                {
                                    entry = *reinterpret_cast<const uint64_t*>(mapped_data.data() + ilt_off);
                                    if (entry == 0)
                                    {
                                        break;
                                    }
                                    if ((entry & (1ULL << 63)) != 0)
                                    {
                                        const auto ord = static_cast<uint16_t>(entry & 0xFFFFu);
                                        const std::string ord_name = "#" + std::to_string(ord);
                                        const uint64_t addr = resolver(dll_name, ord_name);
                                        auto* iat_slot = reinterpret_cast<uint64_t*>(mapped_data.data() + iat_off);
                                        *iat_slot = addr;
                                        continue;
                                    }
                                }
                                else
                                {
                                    entry = *reinterpret_cast<const uint32_t*>(mapped_data.data() + ilt_off);
                                    if (entry == 0)
                                    {
                                        break;
                                    }
                                    if ((entry & 0x80000000u) != 0)
                                    {
                                        const auto ord = static_cast<uint16_t>(entry & 0xFFFFu);
                                        const std::string ord_name = "#" + std::to_string(ord);
                                        const uint64_t addr = resolver(dll_name, ord_name);
                                        auto* iat_slot = reinterpret_cast<uint32_t*>(mapped_data.data() + iat_off);
                                        *iat_slot = static_cast<uint32_t>(addr);
                                        continue;
                                    }
                                }

                                // Name import: RVA points to hint (2 bytes) then ASCII name
                                const auto name_rva = static_cast<uint32_t>(entry & 0x7FFFFFFFu);
                                if (name_rva + 2 >= mapped_data.size())
                                {
                                    break;
                                }
                                std::string_view func_name = string_at_rva(image, name_rva + 2);
                                const uint64_t addr = resolver(dll_name, func_name);
                                if constexpr (is_64)
                                {
                                    auto* iat_slot = reinterpret_cast<uint64_t*>(mapped_data.data() + iat_off);
                                    *iat_slot = addr;
                                }
                                else
                                {
                                    auto* iat_slot = reinterpret_cast<uint32_t*>(mapped_data.data() + iat_off);
                                    *iat_slot = static_cast<uint32_t>(addr);
                                }
                            }

                            ++desc;
                        }
                    }
                }
            }

            return mapped_data;
        }
    }

    std::optional<pe_architecture> get_pe_architecture(std::span<const uint8_t> data)
    {
        constexpr size_t dos_header_size = sizeof(pe_dos_header);
        constexpr size_t file_header_size = sizeof(pe_file_header);

        if (data.size() < dos_header_size)
        {
            return std::nullopt;
        }

        const auto* dos = reinterpret_cast<const pe_dos_header*>(data.data());
        if (dos->e_magic != pe::dos_signature)
        {
            return std::nullopt;
        }

        const uint32_t e_lfanew = dos->e_lfanew;
        const size_t nt_offset = e_lfanew + 4u; // after "PE\0\0"

        if (nt_offset + file_header_size + 2u > data.size()) // need file header + at least magic
        {
            return std::nullopt;
        }

        if (std::memcmp(data.data() + e_lfanew, "PE\0\0", 4) != 0)
        {
            return std::nullopt;
        }

        const auto* file_header = reinterpret_cast<const pe_file_header*>(data.data() + nt_offset);
        const uint16_t optional_magic = *reinterpret_cast<const uint16_t*>(data.data() + nt_offset + file_header_size);

        if (optional_magic == pe::optional_header_magic_32)
        {
            return pe_architecture::x86;
        }

        if (optional_magic == pe::optional_header_magic_64)
        {
            return pe_architecture::x64;
        }

        return std::nullopt;
    }

    std::vector<uint8_t> map_pe_file(std::span<const uint8_t> data, const pe_import_resolver_t& import_resolver)
    {
        constexpr size_t dos_header_size = sizeof(pe_dos_header);
        constexpr size_t file_header_size = sizeof(pe_file_header);

        if (data.size() < dos_header_size)
        {
            return {};
        }

        const auto* dos = reinterpret_cast<const pe_dos_header*>(data.data());
        if (dos->e_magic != pe::dos_signature)
        {
            return {};
        }

        const uint32_t e_lfanew = dos->e_lfanew;
        const size_t nt_offset = e_lfanew + 4u; // after "PE\0\0"

        if (nt_offset + file_header_size + 2u > data.size()) // need file header + at least magic
        {
            return {};
        }

        if (std::memcmp(data.data() + e_lfanew, "PE\0\0", 4) != 0)
        {
            return {};
        }

        const auto* file_header = reinterpret_cast<const pe_file_header*>(data.data() + nt_offset);
        const uint16_t optional_magic = *reinterpret_cast<const uint16_t*>(data.data() + nt_offset + file_header_size);

        const size_t section_table_offset = nt_offset + file_header_size + file_header->size_of_optional_header;

        if (optional_magic == pe::optional_header_magic_32)
        {
            return map_pe_impl<pe_optional_header_32>(data, *file_header, section_table_offset, import_resolver);
        }

        if (optional_magic == pe::optional_header_magic_64)
        {
            return map_pe_impl<pe_optional_header_64>(data, *file_header, section_table_offset, import_resolver);
        }

        return {};
    }

    uint64_t get_entry_point(std::span<const uint8_t> data)
    {
        constexpr size_t dos_header_size = sizeof(pe_dos_header);
        constexpr size_t file_header_size = sizeof(pe_file_header);

        const auto* dos = reinterpret_cast<const pe_dos_header*>(data.data());
        const auto* file_header = reinterpret_cast<const pe_file_header*>(data.data() + dos->e_lfanew);

        const uint32_t e_lfanew = dos->e_lfanew;
        const size_t nt_offset = e_lfanew + 4u; // after "PE\0\0"

        const uint16_t optional_magic = *reinterpret_cast<const uint16_t*>(data.data() + nt_offset + file_header_size);

        if (optional_magic == pe::optional_header_magic_32)
        {
            const auto* optional_header = reinterpret_cast<const pe_optional_header_32*>(data.data() + nt_offset + file_header_size);
            return optional_header->address_of_entry_point;
        }

        if (optional_magic == pe::optional_header_magic_64)
        {
            const auto* optional_header = reinterpret_cast<const pe_optional_header_64*>(data.data() + nt_offset + file_header_size);
            return optional_header->address_of_entry_point;
        }

        return 0;
    }
}
