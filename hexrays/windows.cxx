#ifndef WINDOWS_CXX
#define WINDOWS_CXX

#include "detection.hpp"
#include <windows.h>

auto ida_pro::window_titles::scan() noexcept -> bool
{
    static const std::unordered_set<std::string> ida_titles =
    {
        "IDA", "IDA Pro", "IDA Demo", "IDA Freeware", "IDA View-A", "IDA View-B", "IDA View-C",
        "IDA View-D", "IDA View-E", "IDA View-F", "IDA View-G", "IDA View-H", "IDA View-I",
        "IDA View-J", "IDA View-K", "IDA View-L", "IDA View-M", "IDA View-N", "IDA View-O",
        "IDA View-P", "IDA View-Q", "IDA View-R", "IDA View-S", "IDA View-T", "IDA View-U",
        "IDA View-V", "IDA View-W", "IDA View-X", "IDA View-Y", "IDA View-Z", "IDA Hex View-A",
        "IDA Hex View-B", "IDA Hex View-C", "IDA Hex View-D", "IDA Hex View-E", "IDA Hex View-F",
        "IDA Hex View-G", "IDA Hex View-H", "IDA Hex View-I", "IDA Hex View-J", "IDA Hex View-K",
        "IDA Hex View-L", "IDA Hex View-M", "IDA Hex View-N", "IDA Hex View-O", "IDA Hex View-P",
        "IDA Hex View-Q", "IDA Hex View-R", "IDA Hex View-S", "IDA Hex View-T", "IDA Hex View-U",
        "IDA Hex View-V", "IDA Hex View-W", "IDA Hex View-X", "IDA Hex View-Y", "IDA Hex View-Z",
        "IDA Output", "IDA Structures", "IDA Enums", "IDA Imports", "IDA Exports", "IDA Names",
        "IDA Functions", "IDA Strings", "IDA Signatures", "IDA Segment", "IDA Segment Registers",
        "IDA Local Types", "IDA Type Libraries", "IDA Pseudocode-A", "IDA Pseudocode-B",
        "IDA Pseudocode-C", "IDA Pseudocode-D", "IDA Pseudocode-E", "IDA Pseudocode-F",
        "IDA Pseudocode-G", "IDA Pseudocode-H", "IDA Pseudocode-I", "IDA Pseudocode-J",
        "IDA Pseudocode-K", "IDA Pseudocode-L", "IDA Pseudocode-M", "IDA Pseudocode-N",
        "IDA Pseudocode-O", "IDA Pseudocode-P", "IDA Pseudocode-Q", "IDA Pseudocode-R",
        "IDA Pseudocode-S", "IDA Pseudocode-T", "IDA Pseudocode-U", "IDA Pseudocode-V",
        "IDA Pseudocode-W", "IDA Pseudocode-X", "IDA Pseudocode-Y", "IDA Pseudocode-Z"
    };

    this->title_status = false;

    auto enum_windows_proc = [](HWND hwnd, LPARAM lParam) -> BOOL
        {
            window_titles* self = reinterpret_cast<window_titles*>(lParam);
            char window_title[self->buffer_size];
            GetWindowTextA(hwnd, window_title, self->buffer_size);
            std::string title(window_title);

            for (const auto& ida_title : ida_titles)
            {
                if (title.find(ida_title) != std::string::npos)
                {
                    self->title_status = true;
                    return FALSE;
                }
            }
            return TRUE;
        };

    EnumWindows(enum_windows_proc, reinterpret_cast<LPARAM>(this));
    return this->title_status;
}
#endif
