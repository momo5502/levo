#include "../handler_repository.hpp"
#include "../libs.hpp"
#include <shared/finally.hpp>

namespace levo::runtime
{
    namespace
    {
        addr_t handler_GetStdHandle(const handler_context&, addr_t handle)
        {
            if (handle == (addr_t)-11)
            {
                return 1;
            }

            return (addr_t)~0ULL;
        }

        addr_t handler_WriteFile(const handler_context& c, addr_t handle, addr_t buffer, uint32_t size, addr_t written_size, addr_t)
        {
            size_t written = 0;
            const auto _ = finally([&] {
                if (written_size)
                {
                    c.m.write(written_size, static_cast<uint32_t>(written));
                }
            });

            if (handle != 1)
            {
                return 0;
            }

            const auto string = c.m.read(buffer, size);
            written = fwrite(string->data(), 1, string->size(), stdout);

            return 1;
        }

        void handler_ExitProcess(const handler_context&, uint32_t exit_code)
        {
            exit(static_cast<int>(exit_code));
        }
    }

    namespace lib
    {
        void kernel32(handler_repository& repo)
        {
            REGISTER_LIBRARY("kernel32.dll");
            REGISTER_HANDLER(stdcall, GetStdHandle);
            REGISTER_HANDLER(stdcall, WriteFile);
            REGISTER_HANDLER(stdcall, ExitProcess);
        }
    }
}
