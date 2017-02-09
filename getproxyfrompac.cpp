#include "stdafx.h"
#include <winhttp.h>
#include "resource.h"
#include "SimpleBuffer.h"
#ifndef VTRACE
#   define VTRACE(...) while (false) {}
#endif
#define CLL_NO_ENSURE_VERSION_CLASS
#include "LoadLibrary.h"

extern "C" int _tmain(int argc, _TCHAR* argv[])
{
    CLoadLibrary winhttp(_T("winhttp.dll"));
    if (3 != argc)
    {
        _tprintf(_T("Syntax:\n\t%s <url> <pac-url>\n"), argv[0]);
        return __LINE__;
    }
    LPCTSTR lpszURLtoCheck = argv[1];
    LPCTSTR lpszPacURL = argv[2];
    HINTERNET hInet = ::WinHttpOpen(_T("User"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (NULL == hInet)
    {
        _tprintf(_T("WinHttpOpen failed with %d.\n"), GetLastError());
        CSimpleBuf<TCHAR> errStr = CLoadLibrary::formatMessage<TCHAR>(winhttp.getHandle(), GetLastError());
        _tprintf(_T("\t%s\n"), errStr.Buffer());
        return __LINE__;
    }
    WINHTTP_AUTOPROXY_OPTIONS proxyOptions = { 0 };
    WINHTTP_PROXY_INFO proxyInfo = { 0 };
    proxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
    // BUGBUG: must be zero according to docs:
    proxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    proxyOptions.lpszAutoConfigUrl = lpszPacURL;
    BOOL bProceed = ::WinHttpGetProxyForUrl(hInet, lpszURLtoCheck, &proxyOptions, &proxyInfo);
    if (!bProceed)
    {
        _tprintf(_T("WinHttpGetProxyForUrl failed with %d\n"), GetLastError());
        CSimpleBuf<TCHAR> errStr = CLoadLibrary::formatMessage<TCHAR>(winhttp.getHandle(), GetLastError());
        _tprintf(_T("\t%s\n"), errStr.Buffer());
    }
    if (bProceed)
    {
        _tprintf(_T("access type: %08X\n\n"), proxyInfo.dwAccessType);
        _tprintf(_T("proxy server list: %s\n"), proxyInfo.lpszProxy);
        _tprintf(_T("proxy bypass list: %s\n"), proxyInfo.lpszProxyBypass);
    }
    if (!::WinHttpCloseHandle(hInet))
    {
        _tprintf(_T("Could not close the handle. WinHttpCloseHandle() failed with %d.\n"), GetLastError());
        CSimpleBuf<TCHAR> errStr = CLoadLibrary::formatMessage<TCHAR>(winhttp.getHandle(), GetLastError());
        _tprintf(_T("\t%s\n"), errStr.Buffer());
    }
    return 0;
}
