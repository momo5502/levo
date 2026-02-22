#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <optional>
#include <string_view>
#include <vector>

namespace levo
{
    // Platform-independent PE structure definitions (no Windows.h).
    // Layout matches the PE on-disk format; packed for cross-compiler layout consistency.

#pragma pack(push, 1)

    // DOS header (64 bytes).
    struct pe_dos_header
    {
        uint16_t e_magic;
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        std::array<uint16_t, 4> e_res;
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        std::array<uint16_t, 10> e_res2;
        uint32_t e_lfanew;
    };

    // COFF file header (20 bytes), same for PE32 and PE32+.
    struct pe_file_header
    {
        uint16_t machine;
        uint16_t number_of_sections;
        uint32_t time_date_stamp;
        uint32_t pointer_to_symbol_table;
        uint32_t number_of_symbols;
        uint16_t size_of_optional_header;
        uint16_t characteristics;
    };

    // Data directory entry (8 bytes).
    struct pe_data_directory
    {
        uint32_t virtual_address;
        uint32_t size;
    };

    // Optional header for PE32 (224 bytes typical; size varies with NumberOfRvaAndSizes).
    struct pe_optional_header_32
    {
        uint16_t magic;
        uint8_t major_linker_version;
        uint8_t minor_linker_version;
        uint32_t size_of_code;
        uint32_t size_of_initialized_data;
        uint32_t size_of_uninitialized_data;
        uint32_t address_of_entry_point;
        uint32_t base_of_code;
        uint32_t base_of_data;
        uint32_t image_base;
        uint32_t section_alignment;
        uint32_t file_alignment;
        uint16_t major_operating_system_version;
        uint16_t minor_operating_system_version;
        uint16_t major_image_version;
        uint16_t minor_image_version;
        uint16_t major_subsystem_version;
        uint16_t minor_subsystem_version;
        uint32_t win32_version_value;
        uint32_t size_of_image;
        uint32_t size_of_headers;
        uint32_t check_sum;
        uint16_t subsystem;
        uint16_t dll_characteristics;
        uint32_t size_of_stack_reserve;
        uint32_t size_of_stack_commit;
        uint32_t size_of_heap_reserve;
        uint32_t size_of_heap_commit;
        uint32_t loader_flags;
        uint32_t number_of_rva_and_sizes;
        std::array<pe_data_directory, 16> data_directory;
    };

    // Optional header for PE32+ (240 bytes typical).
    struct pe_optional_header_64
    {
        uint16_t magic;
        uint8_t major_linker_version;
        uint8_t minor_linker_version;
        uint32_t size_of_code;
        uint32_t size_of_initialized_data;
        uint32_t size_of_uninitialized_data;
        uint32_t address_of_entry_point;
        uint32_t base_of_code;
        uint64_t image_base;
        uint32_t section_alignment;
        uint32_t file_alignment;
        uint16_t major_operating_system_version;
        uint16_t minor_operating_system_version;
        uint16_t major_image_version;
        uint16_t minor_image_version;
        uint16_t major_subsystem_version;
        uint16_t minor_subsystem_version;
        uint32_t win32_version_value;
        uint32_t size_of_image;
        uint32_t size_of_headers;
        uint32_t check_sum;
        uint16_t subsystem;
        uint16_t dll_characteristics;
        uint64_t size_of_stack_reserve;
        uint64_t size_of_stack_commit;
        uint64_t size_of_heap_reserve;
        uint64_t size_of_heap_commit;
        uint32_t loader_flags;
        uint32_t number_of_rva_and_sizes;
        std::array<pe_data_directory, 16> data_directory;
    };

    // Section header (40 bytes), same for PE32 and PE32+.
    struct pe_section_header
    {
        std::array<uint8_t, 8> name;
        uint32_t virtual_size;
        uint32_t virtual_address;
        uint32_t size_of_raw_data;
        uint32_t pointer_to_raw_data;
        uint32_t pointer_to_relocations;
        uint32_t pointer_to_linenumbers;
        uint16_t number_of_relocations;
        uint16_t number_of_linenumbers;
        uint32_t characteristics;
    };

    // Import directory entry (20 bytes). Terminated by a null descriptor.
    struct pe_import_descriptor
    {
        uint32_t original_first_thunk; // RVA to ILT (Import Lookup Table)
        uint32_t time_date_stamp;
        uint32_t forwarder_chain;
        uint32_t name;        // RVA to DLL name (ASCII)
        uint32_t first_thunk; // RVA to IAT (Import Address Table)
    };

#pragma pack(pop)

    namespace pe
    {
        constexpr uint16_t dos_signature = 0x5A4D;           // "MZ"
        constexpr uint32_t nt_signature = 0x00004550;        // "PE\0\0"
        constexpr uint16_t optional_header_magic_32 = 0x10b; // PE32
        constexpr uint16_t optional_header_magic_64 = 0x20b; // PE32+
        constexpr unsigned directory_entry_import = 1;       // DataDirectory index for Import Table
    }

    // Import resolver: (library_name, function_name) -> address to store in IAT.
    // For ordinal imports, function_name is "#" + decimal ordinal (e.g. "#42").
    using pe_import_resolver_t = std::function<uint64_t(std::string_view library_name, std::string_view function_name)>;

    // Maps a PE file (from file layout) into a contiguous buffer (load layout).
    // If import_resolver is set, fills the Import Address Table with resolved addresses.
    // Supports both PE32 and PE32+; uses platform-independent structs only.
    std::vector<uint8_t> map_pe_file(std::span<const uint8_t> data, const pe_import_resolver_t& import_resolver = {});

    uint64_t get_entry_point(std::span<const uint8_t> data);

    enum class pe_architecture
    {
        x86,
        x64,
    };

    std::optional<pe_architecture> get_pe_architecture(std::span<const uint8_t> data);
}
