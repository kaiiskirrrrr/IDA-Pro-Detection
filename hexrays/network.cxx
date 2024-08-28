#ifndef NETWORK_CXX
#define NETWORK_CXX

#include "detection.hpp"
#include <iphlpapi.h>
#include <algorithm>
#include <vector>
#include <string>
#include <iostream>

auto ida_pro::network_connections::scan() const noexcept -> bool
{
    const std::vector<std::string> ida_ports = { "23946", "23947", "23948", "23949" };

    MIB_TCPTABLE_OWNER_PID* tcp_table = nullptr;
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (result != ERROR_INSUFFICIENT_BUFFER)
    {
        return false;
    }

    tcp_table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(malloc(size));
    if (!tcp_table)
    {
        return false;
    }

    result = GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR)
    {
        free(tcp_table);
        return false;
    }

    for (DWORD i = 0; i < tcp_table->dwNumEntries; ++i)
    {
        std::string local_port = std::to_string(ntohs(static_cast<u_short>(tcp_table->table[i].dwLocalPort)));
        if (std::find(ida_ports.begin(), ida_ports.end(), local_port) != ida_ports.end())
        {
            free(tcp_table);
            return true;
        }
    }

    free(tcp_table);
    return false;
}

#endif
