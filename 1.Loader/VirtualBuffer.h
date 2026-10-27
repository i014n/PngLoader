#pragma once
#include <windows.h>
#include <wincodec.h>
#include <wrl/client.h>
#include <cstdint>
#include <cstdio>
#include <type_traits>

#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")

class VirtualBuffer {
    void* p_ = nullptr;
public:
    VirtualBuffer() noexcept = default;

    explicit VirtualBuffer(size_t bytes) noexcept {
        // VirtualAlloc(0) fails and sets last-error; treat it as "empty".
        if (bytes) p_ = VirtualAlloc(nullptr, bytes,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    ~VirtualBuffer() { reset(); }

    VirtualBuffer(const VirtualBuffer&) = delete;
    VirtualBuffer& operator=(const VirtualBuffer&) = delete;

    VirtualBuffer(VirtualBuffer&& other) noexcept : p_(other.p_) {
        other.p_ = nullptr;
    }

    VirtualBuffer& operator=(VirtualBuffer&& other) noexcept {
        if (this != &other) {
            reset();
            p_ = other.p_;
            other.p_ = nullptr;
        }
        return *this;
    }

    void reset() noexcept {
        if (p_) { VirtualFree(p_, 0, MEM_RELEASE); p_ = nullptr; }
    }

    uint8_t* get() const noexcept { return static_cast<uint8_t*>(p_); }
    explicit operator bool() const noexcept { return p_ != nullptr; }
};


class ComScope {
    HRESULT hr_;
public:
    ComScope() noexcept : hr_(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ComScope() { if (SUCCEEDED(hr_)) CoUninitialize(); }
    bool ok() const noexcept { return SUCCEEDED(hr_); }
};

static void Fail(const wchar_t* what, HRESULT hr) {
    fwprintf(stderr, L"[!] %s failed (hr = 0x%08X)\n", what, static_cast<unsigned>(hr));
}