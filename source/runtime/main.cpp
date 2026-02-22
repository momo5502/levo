#include "system.hpp"
#include "external.hpp"
#include "execution_manager.hpp"
#include "handler_repository.hpp"

#include <shared/io.hpp>
#include <shared/pe_mapper.hpp>

#include "libs.hpp"

namespace levo::runtime
{
    namespace
    {
        std::vector<uint8_t> map_binary(const pe_import_resolver_t& import_resolver)
        {
            std::span<const uint8_t> data(binary_data, binary_size);
            return map_pe_file(data, import_resolver);
        }

        int run()
        {
            handler_repository repo{};
            register_libs(repo);

            execution_manager manager{};

            addr_t import_address = 0xF << (ADDRESS_SIZE_BITS - 4);

            const auto import_resolver = [&](std::string_view library, std::string_view function) {
                auto* handler = repo.lookup(library, function);
                if (!handler)
                {
                    throw std::runtime_error("Missing handler for " + std::string(library) + "::" + std::string(function));
                }

                const auto address = import_address++;
                manager.add_function(address, handler);
                return address;
            };

            auto binary = map_binary(import_resolver);
            const auto entry_point = get_entry_point(binary);

            manager.map(image_base, std::move(binary));

            constexpr size_t stack_size = 0x100000;
            const auto stack_address = manager.map_somewhere(stack_size);

            for (size_t i = 0;; i++)
            {
                const auto& entry = dispatch_table[i];
                if (entry.address == 0)
                {
                    break;
                }

                manager.add_function(entry.address, entry.function);
            }

            State state{};
            state.gpr.rip.aword = static_cast<addr_t>(image_base + entry_point);
            state.gpr.rsp.aword = align_down(stack_address + stack_size - 0x10, 0x10);

            manager.run(state);

            return 0;
        }
    }
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    try
    {
        return levo::runtime::run();
    }
    catch (const std::exception& e)
    {
        printf("Error: %s\n", e.what());
    }
}
