#include "../handler_repository.hpp"
#include "../libs.hpp"
#include <shared/finally.hpp>
#include <chrono>

namespace levo::runtime
{
    namespace
    {
        using DWORD = uint32_t;
        using BOOL = int32_t;
        using BYTE = uint8_t;
        using WORD = uint16_t;
        using FLOAT = float32_t;

        thread_local DWORD last_error = 0;

        std::atomic<uint32_t> globalthread_id = 0;
        thread_local uint32_t current_thread_id = ++globalthread_id;

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

        void handler_GetSystemTimeAsFileTime(const handler_context& c, addr_t file_time_ptr)
        {
            constexpr auto HUNDRED_NANOSECONDS_IN_ONE_SECOND = 10000000LL;
            constexpr auto EPOCH_DIFFERENCE_1601_TO_1970_SECONDS = 11644473600LL;

            auto now = std::chrono::system_clock::now();
            auto now_time_t = std::chrono::system_clock::to_time_t(now);

            const uint64_t time = (now_time_t * HUNDRED_NANOSECONDS_IN_ONE_SECOND) + EPOCH_DIFFERENCE_1601_TO_1970_SECONDS;
            c.m.write(file_time_ptr, time);
        }

        uint32_t handler_GetCurrentThreadId(const handler_context&)
        {
            return current_thread_id;
        }

        uint32_t handler_GetCurrentProcessId(const handler_context&)
        {
            return 1;
        }

        BOOL handler_QueryPerformanceCounter(const handler_context& c, addr_t counter)
        {
            if (!counter)
            {
                return 0;
            }

            const auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
            const uint64_t result = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();

            c.m.write(counter, result);

            return true;
        }

        BOOL handler_IsProcessorFeaturePresent(const handler_context&, DWORD)
        {
            return 1;
        }

        addr_t handler_LoadLibraryExW(const handler_context&, addr_t, addr_t, DWORD)
        {
            return 0;
        }

        DWORD handler_GetLastError(const handler_context&)
        {
            return last_error;
        }

        void handler_SetLastError(const handler_context&, DWORD error)
        {
            last_error = error;
        }

        BOOL handler_InitializeCriticalSectionAndSpinCount(const handler_context&, addr_t, DWORD)
        {
            return 1;
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
            REGISTER_HANDLER(stdcall, GetSystemTimeAsFileTime);
            REGISTER_HANDLER(stdcall, GetCurrentThreadId);
            REGISTER_HANDLER(stdcall, GetCurrentProcessId);
            REGISTER_HANDLER(stdcall, QueryPerformanceCounter);
            REGISTER_HANDLER(stdcall, IsProcessorFeaturePresent);
            REGISTER_HANDLER(stdcall, LoadLibraryExW);
            REGISTER_HANDLER(stdcall, GetLastError);
            REGISTER_HANDLER(stdcall, SetLastError);
            REGISTER_HANDLER(stdcall, InitializeCriticalSectionAndSpinCount);
        }
    }
}
