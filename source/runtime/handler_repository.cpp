#include "handler_repository.hpp"
#include <cassert>

namespace levo::runtime
{
    system_function* handler_repository::lookup(const std::string_view library, const std::string_view function) const
    {
#ifndef NDEBUG
        lookup_done_ = true;
#endif

        const auto library_entry = handlers_.find(make_ci_string_view(library));
        if (library_entry == handlers_.end())
        {
            return nullptr;
        }

        const auto function_entry = library_entry->second.find(make_ci_string_view(function));
        if (function_entry == library_entry->second.end())
        {
            return nullptr;
        }

        return function_entry->second;
    }

    void handler_repository::add(const std::string_view library, const std::string_view function, system_function* handler)
    {
        assert(!lookup_done_ && "Can not add handlers after the first lookup has been done!");
        handlers_[make_ci_string_view(library)][make_ci_string_view(function)] = handler;
    }
}
