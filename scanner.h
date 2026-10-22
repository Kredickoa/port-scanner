#pragma once
#include <atomic>
#include <string>
#include <vector>

enum class PortState { Open, Closed, Timeout, Error, Cancelled };
struct PortResult {
    int port = 0;
    PortState state = PortState::Cancelled;
    int error = 0;
};

std::vector<int> parse_ports(const std::wstring& text);
std::vector<PortResult> scan_ports(const std::wstring& ipv4, const std::vector<int>& ports,
    int timeout_ms, std::atomic<bool>& cancel, std::atomic<int>& completed);
std::wstring format_report(const std::wstring& ipv4, int requested, int timeout_ms,
    const std::vector<PortResult>& results, bool cancelled, bool only_open);
