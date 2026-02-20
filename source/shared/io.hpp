#include <fstream>
#include <filesystem>
#include <vector>

namespace levo
{
    inline bool read_file(const std::filesystem::path& file, std::vector<uint8_t>& data)
    {
        data.clear();

        std::ifstream file_stream(file, std::ios::binary);
        if (!file_stream)
        {
            return false;
        }

        std::vector<char> temp_buffer(0x1000);

        while (file_stream)
        {
            file_stream.read(temp_buffer.data(), static_cast<std::streamsize>(temp_buffer.size()));
            const auto bytes_read = file_stream.gcount();

            if (bytes_read > 0)
            {
                const auto* buffer = reinterpret_cast<const uint8_t*>(temp_buffer.data());
                data.insert(data.end(), buffer, buffer + bytes_read);
            }
        }

        return true;
    }

    inline std::vector<uint8_t> read_file(const std::filesystem::path& file)
    {
        std::vector<uint8_t> data{};
        if (!read_file(file, data))
        {
            return {};
        }

        return data;
    }
}
