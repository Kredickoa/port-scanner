#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <thread>
#include "scanner.h"

#ifdef _MSC_VER
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
constexpr int Start = 101, Stop = 102, Save = 103, OnlyOpen = 104;
constexpr UINT Finished = WM_APP + 1;
struct Application {
    HWND window{}, host{}, ports{}, timeout{}, start{}, stop{}, save{}, filter{}, progress{}, status{}, output{};
    HFONT font{}, mono{};
    std::thread worker;
    std::atomic<bool> cancel{false};
    std::atomic<int> completed{0};
    bool busy = false, closing = false;
    int wait_ms = 500;
    std::wstring target, error;
    std::vector<int> selected;
    std::vector<PortResult> results;
} app;

std::wstring wide(const std::string& value) {
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), size);
    return result;
}
std::wstring text(HWND control) {
    std::wstring value(GetWindowTextLengthW(control) + 1, L'\0');
    GetWindowTextW(control, value.data(), static_cast<int>(value.size()));
    value.resize(wcslen(value.c_str()));
    return value;
}
HWND widget(const wchar_t* type, const wchar_t* label, DWORD style,
    int x, int y, int width, int height, int id = 0) {
    HWND item = CreateWindowW(type, label, WS_CHILD | WS_VISIBLE | style, x, y, width, height,
        app.window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(item, WM_SETFONT, reinterpret_cast<WPARAM>(app.font), TRUE);
    return item;
}
void busy(bool value) {
    app.busy = value;
    for (HWND control : {app.host, app.ports, app.timeout, app.start}) EnableWindow(control, !value);
    EnableWindow(app.stop, value);
    EnableWindow(app.save, !value && !app.results.empty());
}
void display_report() {
    if (app.busy || app.selected.empty()) return;
    const bool filtered = SendMessageW(app.filter, BM_GETCHECK, 0, 0) == BST_CHECKED;
    SetWindowTextW(app.output, format_report(app.target, static_cast<int>(app.selected.size()),
        app.wait_ms, app.results, app.cancel.load(), filtered).c_str());
}
void start_scan() {
    const auto selected = parse_ports(text(app.ports));
    const std::wstring host = text(app.host);
    const std::wstring timeout = text(app.timeout);
    if (timeout.empty() || timeout.size() > 4 || !std::all_of(timeout.begin(), timeout.end(),
        [](wchar_t c) { return c >= L'0' && c <= L'9'; }))
        throw std::runtime_error("Timeout must be 100-3000 ms.");
    const int wait = std::stoi(timeout);
    if (wait < 100 || wait > 3000) throw std::runtime_error("Timeout must be 100-3000 ms.");
    app.selected = selected; app.target = host; app.wait_ms = wait;
    app.results.clear(); app.error.clear(); app.cancel = false; app.completed = 0;
    SetWindowTextW(app.output, L"Scanning selected TCP ports...\r\nResults will appear when the scan finishes or is stopped.");
    SendMessageW(app.progress, PBM_SETRANGE32, 0, selected.size());
    SendMessageW(app.progress, PBM_SETPOS, 0, 0);
    busy(true);
    try {
        app.worker = std::thread([] {
            try { app.results = scan_ports(app.target, app.selected, app.wait_ms, app.cancel, app.completed); }
            catch (const std::exception& error) { app.error = wide(error.what()); }
            PostMessageW(app.window, Finished, 0, 0);
        });
    } catch (...) { busy(false); throw; }
    SetTimer(app.window, 1, 150, nullptr);
}
void save_report() {
    wchar_t filename[32768] = L"report.txt";
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog); dialog.hwndOwner = app.window;
    dialog.lpstrFilter = L"Text report\0*.txt\0"; dialog.lpstrFile = filename;
    dialog.nMaxFile = 32768; dialog.lpstrDefExt = L"txt";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&dialog)) return;
    const auto report = format_report(app.target, static_cast<int>(app.selected.size()),
        app.wait_ms, app.results, app.cancel.load(), false);
    const int size = WideCharToMultiByte(CP_UTF8, 0, report.data(), static_cast<int>(report.size()), nullptr, 0, nullptr, nullptr);
    std::string bytes(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, report.data(), static_cast<int>(report.size()), bytes.data(), size, nullptr, nullptr);
    std::ofstream file(std::filesystem::path(filename), std::ios::binary);
    file << bytes; file.close();
    if (!file) throw std::runtime_error("Could not save the report.");
    SetWindowTextW(app.status, L"Full report saved.");
}
LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        app.window = window;
        app.font = CreateFontW(-17, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        app.mono = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH, L"Consolas");
        widget(L"STATIC", L"TCP PORT SCANNER", 0, 20, 16, 300, 26);
        widget(L"STATIC", L"IPv4 address", 0, 20, 57, 100, 24);
        app.host = widget(L"EDIT", L"127.0.0.1", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 130, 53, 180, 28);
        SendMessageW(app.host, EM_SETLIMITTEXT, 15, 0);
        widget(L"STATIC", L"Timeout (ms)", 0, 340, 57, 110, 24);
        app.timeout = widget(L"EDIT", L"500", WS_BORDER | WS_TABSTOP | ES_NUMBER, 460, 53, 75, 28);
        SendMessageW(app.timeout, EM_SETLIMITTEXT, 4, 0);
        widget(L"STATIC", L"TCP ports", 0, 20, 100, 100, 24);
        app.ports = widget(L"EDIT", L"22,80,443,3000,8000,8080", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 130, 96, 480, 28);
        SendMessageW(app.ports, EM_SETLIMITTEXT, 8192, 0);
        app.start = widget(L"BUTTON", L"Scan", WS_TABSTOP, 20, 140, 100, 32, Start);
        app.stop = widget(L"BUTTON", L"Stop", WS_TABSTOP, 130, 140, 100, 32, Stop);
        app.save = widget(L"BUTTON", L"Save report...", WS_TABSTOP, 240, 140, 140, 32, Save);
        app.filter = widget(L"BUTTON", L"Only open ports", WS_TABSTOP | BS_AUTOCHECKBOX, 405, 142, 175, 28, OnlyOpen);
        SendMessageW(app.filter, BM_SETCHECK, BST_CHECKED, 0);
        app.progress = widget(PROGRESS_CLASSW, L"", 0, 20, 188, 800, 12);
        app.status = widget(L"STATIC", L"Single host, TCP connect scan. Up to 4096 ports, 16 workers.", 0, 20, 212, 800, 24);
        app.output = widget(L"EDIT", L"Choose ports such as 22,80,443 or a range such as 8000-8010.\r\nUse on your own devices or systems you have permission to test.",
            WS_BORDER | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            20, 248, 800, 400);
        SendMessageW(app.output, WM_SETFONT, reinterpret_cast<WPARAM>(app.mono), TRUE);
        SendMessageW(app.output, EM_SETLIMITTEXT, 1000000, 0);
        busy(false);
        return 0;
    case WM_SIZE: {
        const int width = LOWORD(lparam), height = HIWORD(lparam);
        MoveWindow(app.progress, 20, 188, std::max(1, width - 40), 12, TRUE);
        MoveWindow(app.status, 20, 212, std::max(1, width - 40), 24, TRUE);
        MoveWindow(app.output, 20, 248, std::max(1, width - 40), std::max(1, height - 268), TRUE);
        return 0;
    }
    case WM_GETMINMAXINFO:
        reinterpret_cast<MINMAXINFO*>(lparam)->ptMinTrackSize = {680, 520}; return 0;
    case WM_CTLCOLORSTATIC:
        SetBkColor(reinterpret_cast<HDC>(wparam), RGB(255, 255, 255));
        SetTextColor(reinterpret_cast<HDC>(wparam), RGB(30, 30, 30));
        return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
    case WM_TIMER: {
        const int done = app.completed.load();
        SendMessageW(app.progress, PBM_SETPOS, done, 0);
        const auto status = L"Checked " + std::to_wstring(done) + L" / " + std::to_wstring(app.selected.size());
        SetWindowTextW(app.status, status.c_str()); return 0;
    }
    case Finished:
        KillTimer(window, 1);
        if (app.worker.joinable()) app.worker.join();
        busy(false);
        if (app.closing) { DestroyWindow(window); return 0; }
        if (!app.error.empty()) {
            SetWindowTextW(app.output, app.error.c_str()); SetWindowTextW(app.status, L"Scan failed.");
        } else {
            display_report(); SetWindowTextW(app.status, app.cancel ? L"Stopped. Partial results are available." : L"Scan finished.");
        }
        SendMessageW(app.progress, PBM_SETPOS, app.completed.load(), 0);
        return 0;
    case WM_COMMAND:
        if (HIWORD(wparam) != BN_CLICKED) break;
        try {
            switch (LOWORD(wparam)) {
            case Start: if (!app.busy) start_scan(); break;
            case Stop: app.cancel = true; SetWindowTextW(app.status, L"Stopping..."); break;
            case Save: if (!app.busy) save_report(); break;
            case OnlyOpen: display_report(); break;
            }
        } catch (const std::exception& error) {
            MessageBoxW(window, wide(error.what()).c_str(), L"Port Scanner", MB_OK | MB_ICONERROR);
        }
        return 0;
    case WM_CLOSE:
        if (app.busy) { app.closing = true; app.cancel = true; SetWindowTextW(app.status, L"Stopping before closing..."); }
        else DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        DeleteObject(app.font); DeleteObject(app.mono); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    SetProcessDPIAware();
    INITCOMMONCONTROLSEX common{sizeof(common), ICC_PROGRESS_CLASS}; InitCommonControlsEx(&common);
    WNDCLASSW window{};
    window.lpfnWndProc = window_proc; window.hInstance = instance; window.lpszClassName = L"JuniorPortScanner";
    window.hCursor = LoadCursorW(nullptr, IDC_ARROW); window.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassW(&window)) return 1;
    HWND handle = CreateWindowW(window.lpszClassName, L"Port Scanner", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 940, 760, nullptr, nullptr, instance, nullptr);
    if (!handle) return 1;
    ShowWindow(handle, show);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(handle, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
    }
    return static_cast<int>(message.wParam);
}
