#pragma once

namespace levo::runtime
{
    class handler_repository;

    namespace lib
    {
        void kernel32(handler_repository& repo);
    }

    inline void register_libs(handler_repository& repo)
    {
        lib::kernel32(repo);
    }
}
