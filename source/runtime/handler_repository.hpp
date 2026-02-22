#pragma once

#include "handler_utils.hpp"
#include "ci_string.hpp"

#define REGISTER_LIBRARY(name)     const std::string_view g_handler_library = name
#define REGISTER_HANDLER(cc, name) repo.add(g_handler_library, #name, make_handler<calling_convention::cc, handler_##name>());

namespace levo::runtime
{
    class handler_repository
    {
      public:
        system_function* lookup(std::string_view library, std::string_view function) const;
        void add(std::string_view library, std::string_view function, system_function* handler);

      private:
        ci_string_view_map<ci_string_view_map<system_function*>> handlers_{};

#ifndef NDEBUG
        mutable bool lookup_done_{false};
#endif
    };
}
