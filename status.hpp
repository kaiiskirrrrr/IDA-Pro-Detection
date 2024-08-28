#ifndef STATUS_HPP
#define STATUS_HPP

#include "detection.hpp"

class blacklist
{
public:
    void initialize()
    {
        // handle blacklist
    }
};
inline const auto c_blacklist = std::make_unique<blacklist>();

class status
{
private:
    bool window_title = { false };
    bool process_list = { false };
    bool module_list = { false };
    bool registry = { false };
    bool file_system = { false };
    bool network_connection = { false };
    bool copyright = {false };

    auto print_trace(const std::string& name, bool status) const -> void
    {
        std::cout << name << ": " << (status ? "\033[32m✔ true\033[0m" : "\033[33m✘ false\033[0m") << std::endl;
    }


    auto print_active(const std::string& name, bool status) const -> void
    {
        std::cout << name << ": " << (status ? "\033[32m✔ true\033[0m" : "\033[31m✘ false\033[0m") << std::endl;
    }

public:
    auto start() noexcept -> void
    {
        constexpr bool check_traces = { true };

        std::unordered_map<std::string, bool> current_status =
        {
            {"window_titles", !this->window_title},
            {"process_list", !this->process_list},
            {"module_list", !this->module_list},
            {"network_connection", !this->network_connection},
            {"copyright", !this->copyright}
        };

        std::unordered_map<std::string, std::function<bool()>> checks =
        {
            {"window_titles", [&]() { return c_ida_pro->c_window.scan(); }},
            {"process_list", [&]() { return c_ida_pro->c_processes.scan(); }},
            {"module_list", [&]() { return c_ida_pro->c_modules.scan(); }},
            {"network_connection", [&]() { return c_ida_pro->c_network.scan(); }},
            {"copyright", [&]() { return c_ida_pro->c_copyright.scan(); }}
        };

        std::unordered_map<std::string, bool> trace_status =
        {
            {"registry", !this->registry},
            {"file_system", !this->file_system}
        };

        std::unordered_map<std::string, std::function<bool()>> trace_checks =
        {
            {"registry", [&]() { return c_ida_pro->c_registry.scan(); }},
            {"file_system", [&]() { return c_ida_pro->c_files.scan(); }}
        };

        while (true)
        {
            bool status_changed = false;

            for (auto& [key, check] : checks)
            {
                bool new_status = check();
                if (new_status != current_status[key])
                {
                    current_status[key] = new_status;
                    status_changed = true;
                }
            }

            for (auto& [key, check] : trace_checks)
            {
                bool new_status = check();
                if (new_status != trace_status[key])
                {
                    trace_status[key] = new_status;
                    status_changed = true;
                }
            }

            if (status_changed)
            {
                system("cls");
                std::cout << "[-------Active-------]" << std::endl;
                for (const auto& [key, status] : current_status)
                {
                    this->print_active("[->] " + key, status);

                    if (status)
                    {
                        // handle blacklist
                    }
                }

                if (check_traces)
                {
                    std::cout << "\n[-------Traces-------]" << std::endl;
                    for (const auto& [key, status] : trace_status)
                    {
                        this->print_trace("[->] " + key, status);

                        if (status)
                        {
                            // handle blacklist
                        }
                    }
                }
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
};
inline const auto c_status = std::make_unique<status>();
#endif