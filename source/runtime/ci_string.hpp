#pragma once
#include <cctype>
#include <map>
#include <string_view>

namespace levo::runtime
{
    struct ci_char_traits : public std::char_traits<char>
    {
        static char lower(char v)
        {
            return static_cast<char>(tolower(static_cast<uint8_t>(v)));
        }

        static bool eq(char c1, char c2)
        {
            return lower(c1) == lower(c2);
        }
        static bool ne(char c1, char c2)
        {
            return lower(c1) != lower(c2);
        }
        static bool lt(char c1, char c2)
        {
            return lower(c1) < lower(c2);
        }
        static int compare(const char* s1, const char* s2, size_t n)
        {
            while (n-- != 0)
            {
                if (lower(*s1) < lower(*s2))
                {
                    return -1;
                }

                if (lower(*s1) > lower(*s2))
                {
                    return 1;
                }

                ++s1;
                ++s2;
            }
            return 0;
        }
        static const char* find(const char* s, int n, char a)
        {
            while (n-- > 0 && lower(*s) != lower(a))
            {
                ++s;
            }
            return s;
        }
    };

    using ci_string_view = std::basic_string_view<char, ci_char_traits>;

    template <typename T>
    using ci_string_view_map = std::map<ci_string_view, T, std::less<>>;

    inline ci_string_view make_ci_string_view(const std::string_view view)
    {
        return {view.data(), view.size()};
    }
}
