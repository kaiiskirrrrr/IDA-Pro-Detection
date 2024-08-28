#ifndef DETECTION_HPP
#define DETECTION_HPP

#include <vector>
#include <string>
#include <windows.h>
#include <unordered_set>
#include <memory>

class ida_pro
{
public:

    class process_list
    {
    public:
        auto scan() const noexcept -> bool;
    };
    process_list c_processes;

    class copyright
    {
    private:

        struct LANGANDCODEPAGE
        {
            WORD wLanguage;
            WORD wCodePage;
        } *lpTranslate;

        const std::string product_name = "The Interactive Disassembler";
        const std::string file_description = "The Interactive Disassembler";
        const std::string original_name = "ida.exe";
        const std::string original_name_64 = "ida64.exe";

        auto check_copyright(const std::string& file_path) -> bool;
        auto get_running_executables() -> std::vector<std::string>;

    public:
        auto scan() -> bool;
    };
    copyright c_copyright;

    class module_list
    {
    public:
        auto scan() const noexcept -> bool;
    };
    module_list c_modules;

    class registry_keys
    {
    public:
        auto scan() const noexcept -> bool;
    };
    registry_keys c_registry;

    class window_titles
    {
    private:
        bool title_status = false;
        static constexpr int buffer_size = 256;

    public:
        auto scan() noexcept -> bool;
    };
    window_titles c_window;

    class file_list
    {
    private:
        auto search_directory(const std::string& directory, const std::vector<std::string>& filenames) const noexcept -> bool;

    public:
        auto scan() const noexcept -> bool;
    };
    file_list c_files;

    class network_connections
    {
    public:
        auto scan() const noexcept -> bool;
    };
    network_connections c_network;

}; inline const auto c_ida_pro = std::make_unique<ida_pro>();
#endif
