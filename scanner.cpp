#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include "scanner.h"
#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace {
int port_number(std::wstring text) {
    const auto first = text.find_first_not_of(L" \t\r\n");
    text = first == std::wstring::npos ? L"" : text.substr(first, text.find_last_not_of(L" \t\r\n") - first + 1);
    if (text.empty() || text.size() > 5 || !std::all_of(text.begin(), text.end(),
        [](wchar_t c) { return c >= L'0' && c <= L'9'; })) {
        throw std::runtime_error("Use ports such as 22,80,443 or a range such as 8000-8010.");
    }
    const int value = std::stoi(text);
    if (value < 1 || value > 65535) throw std::runtime_error("Ports must be between 1 and 65535.");
    return value;
}

struct Winsock {
    Winsock() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data)) throw std::runtime_error("Cannot initialise Winsock.");
    }
    ~Winsock() { WSACleanup(); }
};
struct Socket {
    SOCKET value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
};

PortResult probe(sockaddr_in address, int port, int timeout, const std::atomic<bool>& cancel) {
    PortResult result{port, PortState::Error, 0};
    Socket connection;
    if (connection.value == INVALID_SOCKET) { result.error = WSAGetLastError(); return result; }
    u_long nonblocking = 1;
    if (ioctlsocket(connection.value, FIONBIO, &nonblocking)) {
        result.error = WSAGetLastError(); return result;
    }
    address.sin_port = htons(static_cast<u_short>(port));
    if (connect(connection.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0) {
        result.state = PortState::Open; return result;
    }
    int error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK) {
        result.state = error == WSAECONNREFUSED ? PortState::Closed : PortState::Error;
        result.error = error; return result;
    }
    for (int elapsed = 0; elapsed < timeout && !cancel.load(); elapsed += 100) {
        fd_set writable, failed;
        FD_ZERO(&writable); FD_ZERO(&failed);
        FD_SET(connection.value, &writable); FD_SET(connection.value, &failed);
        timeval wait{0, std::min(100, timeout - elapsed) * 1000};
        const int ready = select(0, nullptr, &writable, &failed, &wait);
        if (ready == SOCKET_ERROR) { result.error = WSAGetLastError(); return result; }
        if (!ready) continue;
        int length = sizeof(error);
        if (getsockopt(connection.value, SOL_SOCKET, SO_ERROR,
            reinterpret_cast<char*>(&error), &length)) {
            result.error = WSAGetLastError(); return result;
        }
        result.error = error;
        result.state = error == 0 ? PortState::Open
            : error == WSAECONNREFUSED ? PortState::Closed
            : error == WSAETIMEDOUT ? PortState::Timeout : PortState::Error;
        return result;
    }
    result.state = cancel.load() ? PortState::Cancelled : PortState::Timeout;
    return result;
}

const wchar_t* usual_service(int port) {
    switch (port) {
    case 21: return L"FTP"; case 22: return L"SSH"; case 23: return L"Telnet";
    case 25: return L"SMTP"; case 53: return L"DNS (TCP)"; case 80: return L"HTTP";
    case 110: return L"POP3"; case 135: return L"RPC"; case 139: return L"NetBIOS";
    case 143: return L"IMAP"; case 443: return L"HTTPS"; case 445: return L"SMB";
    case 587: return L"SMTP submission"; case 993: return L"IMAPS";
    case 3000: return L"Development server"; case 3306: return L"MySQL";
    case 3389: return L"RDP"; case 5432: return L"PostgreSQL";
    case 6379: return L"Redis"; case 8000: case 8080: return L"HTTP / development";
    default: return L"Unknown";
    }
}
}

std::vector<int> parse_ports(const std::wstring& text) {
    if (text.empty() || text.back() == L',') throw std::runtime_error("Enter at least one valid port.");
    std::set<int> unique;
    std::wistringstream stream(text);
    std::wstring part;
    while (std::getline(stream, part, L',')) {
        const auto dash = part.find(L'-');
        const int first = port_number(part.substr(0, dash));
        const int last = dash == std::wstring::npos ? first : port_number(part.substr(dash + 1));
        if (last < first) throw std::runtime_error("A port range must run from low to high.");
        if (last - first + 1 > 4096) throw std::runtime_error("Choose at most 4096 distinct ports per scan.");
        for (int port = first; port <= last; ++port) unique.insert(port);
        if (unique.size() > 4096) throw std::runtime_error("Choose at most 4096 distinct ports per scan.");
    }
    return {unique.begin(), unique.end()};
}

std::vector<PortResult> scan_ports(const std::wstring& ipv4, const std::vector<int>& ports,
    int timeout_ms, std::atomic<bool>& cancel, std::atomic<int>& completed) {
    if (ports.empty() || ports.size() > 4096 || timeout_ms < 100 || timeout_ms > 3000)
        throw std::runtime_error("Invalid scan size or timeout (100-3000 ms).");
    if (std::any_of(ports.begin(), ports.end(), [](int p) { return p < 1 || p > 65535; }))
        throw std::runtime_error("Port is outside 1-65535.");
    Winsock runtime;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    if (InetPtonW(AF_INET, ipv4.c_str(), &address.sin_addr) != 1)
        throw std::runtime_error("Enter one IPv4 address, for example 127.0.0.1. Hostnames and address ranges are not supported.");
    if (address.sin_addr.S_un.S_addr == INADDR_ANY || address.sin_addr.S_un.S_addr == INADDR_BROADCAST
        || IN_MULTICAST(ntohl(address.sin_addr.S_un.S_addr)))
        throw std::runtime_error("Choose a unicast IPv4 address.");
    std::vector<PortResult> results(ports.size());
    std::atomic<std::size_t> next{0};
    std::vector<std::thread> workers;
    try {
        for (std::size_t i = 0; i < std::min<std::size_t>(16, ports.size()); ++i) {
            workers.emplace_back([&] {
                while (!cancel.load()) {
                    const auto index = next.fetch_add(1);
                    if (index >= ports.size()) break;
                    results[index] = probe(address, ports[index], timeout_ms, cancel);
                    if (results[index].state != PortState::Cancelled) completed.fetch_add(1);
                }
            });
        }
    } catch (...) {
        cancel = true;
        for (auto& worker : workers) worker.join();
        throw;
    }
    for (auto& worker : workers) worker.join();
    results.erase(std::remove_if(results.begin(), results.end(), [](const PortResult& r) {
        return r.state == PortState::Cancelled;
    }), results.end());
    return results;
}

std::wstring format_report(const std::wstring& ipv4, int requested, int timeout_ms,
    const std::vector<PortResult>& results, bool cancelled, bool only_open) {
    int open = 0, closed = 0, timeout = 0, errors = 0;
    for (const auto& result : results) {
        if (result.state == PortState::Open) ++open;
        else if (result.state == PortState::Closed) ++closed;
        else if (result.state == PortState::Timeout) ++timeout;
        else ++errors;
    }
    std::wostringstream report;
    report << L"TCP PORT SCANNER\r\nTarget: " << ipv4 << L"\r\nTimeout: " << timeout_ms
        << L" ms | Workers: up to 16\r\n" << (cancelled ? L"Stopped" : L"Finished") << L": "
        << results.size() << L" / " << requested << L" checked\r\n\r\n"
        << L"Open: " << open << L" | Closed: " << closed << L" | Timed out: " << timeout
        << L" | Errors: " << errors << L"\r\n\r\n"
        << L"PORT    STATE       USUAL SERVICE (not verified)\r\n"
        << L"------------------------------------------------------\r\n";
    for (const auto& result : results) {
        if (only_open && result.state != PortState::Open) continue;
        const wchar_t* state = result.state == PortState::Open ? L"OPEN"
            : result.state == PortState::Closed ? L"CLOSED"
            : result.state == PortState::Timeout ? L"TIMEOUT" : L"ERROR";
        report << std::left << std::setw(8) << result.port << std::setw(12) << state << usual_service(result.port);
        if (result.error && result.state == PortState::Error) report << L" (Winsock " << result.error << L")";
        report << L"\r\n";
    }
    if (only_open && !open) report << L"No open TCP ports observed in this selection.\r\n";
    report << L"\r\nTimeout means no connection completed before the deadline; it does not prove a port is closed.\r\n";
    return report.str();
}
