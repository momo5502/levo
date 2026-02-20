#pragma once
#include "calling_convention.hpp"

namespace levo::runtime
{
    struct handler_context
    {
        State& s;
        Memory& m;
    };

    namespace detail
    {
        template <calling_convention CC, typename T>
        // Bigger arguments are not supported yet
        // 64 bit values need to be aligned on the stack,
        // so simply tracking the index is not enough
            requires(sizeof(T) <= sizeof(addr_t))
        T resolve_indexed_argument(const handler_context& c, uint32_t& index)
        {
            const auto result = read_argument(c.m, c.s, CC, index++);
            return static_cast<T>(*result);
        }

        // Technically, this can vary depending on type and calling convention
        // and should be moved to calling_convention.hpp
        template <typename Result>
        void store_result(State& state, const Result& res)
        {
            if (ADDRESS_SIZE_BITS == 64 || sizeof(res) <= sizeof(addr_t))
            {
                state.gpr.rax.aword = static_cast<addr_t>(res);
            }
            else
            {
                state.gpr.rax.aword = static_cast<addr_t>(res);
                state.gpr.rdx.aword = static_cast<addr_t>(res >> ADDRESS_SIZE_BITS);
            }
        }

        template <calling_convention CC, typename Result, typename... Args>
        void forward_handler(const handler_context& c, Result (*handler)(const handler_context&, Args...))
        {
            uint32_t index = 0;

            std::tuple<const handler_context&, Args...> func_args{
                c,
                resolve_indexed_argument<CC, std::remove_cv_t<std::remove_reference_t<Args>>>(c, index)...,
            };

            if constexpr (std::is_same_v<Result, void>)
            {
                std::apply(handler, std::move(func_args));
            }
            else
            {
                const auto ret = std::apply(handler, std::move(func_args));
                store_result<Result>(c.s, ret);
            }

            return_function(c.m, c.s, CC, index);
        }
    }

    template <calling_convention CC, auto Handler>
    system_function* make_handler()
    {
        return +[](State& state, addr_t, Memory* memory) {
            handler_context c{
                .s = state,
                .m = *memory,
            };

            detail::forward_handler<CC>(c, Handler);
            return memory;
        };
    }
}
