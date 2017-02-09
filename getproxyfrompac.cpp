#include "stdafx.h"
#include <winhttp.h>
#include "SimpleBuffer.h"
#ifndef VTRACE
#   define VTRACE(...) while (false) {}
#endif
#define CLL_NO_ENSURE_VERSION_CLASS
#include "LoadLibrary.h"

void printAccessType(DWORD accessType)
{
    switch (accessType)
    {
    case WINHTTP_ACCESS_TYPE_DEFAULT_PROXY:
        _tprintf(_T("WINHTTP_ACCESS_TYPE_DEFAULT_PROXY\n"));
        break;
    case WINHTTP_ACCESS_TYPE_NO_PROXY:
        _tprintf(_T("WINHTTP_ACCESS_TYPE_NO_PROXY\n"));
        break;
    case WINHTTP_ACCESS_TYPE_NAMED_PROXY:
        _tprintf(_T("WINHTTP_ACCESS_TYPE_NAMED_PROXY\n"));
        break;
    default:
        _tprintf(_T("unknown access type: %08X\n"), accessType);
        break;
    }
}

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
    HINTERNET hInet = ::WinHttpOpen(_T("User"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (NULL == hInet)
    {
        _tprintf(_T("WinHttpOpen failed with %d.\n"), GetLastError());
        CSimpleBuf<TCHAR> errStr = CLoadLibrary::formatMessage<TCHAR>(winhttp.getHandle(), GetLastError());
        _tprintf(_T("\t%s\n"), errStr.Buffer());
        return __LINE__;
    }
    WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions = { 0 };
    WINHTTP_PROXY_INFO proxyInfo = { 0 };
    autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
    autoProxyOptions.dwAutoDetectFlags = 0 /* the .NET version passed: WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A */;
    autoProxyOptions.lpszAutoConfigUrl = lpszPacURL;
    BOOL bProceed = ::WinHttpGetProxyForUrl(hInet, lpszURLtoCheck, &autoProxyOptions, &proxyInfo);
    if (!bProceed)
    {
        _tprintf(_T("WinHttpGetProxyForUrl failed with %d\n"), GetLastError());
        CSimpleBuf<TCHAR> errStr = CLoadLibrary::formatMessage<TCHAR>(winhttp.getHandle(), GetLastError());
        _tprintf(_T("\t%s\n"), errStr.Buffer());
    }
    if (bProceed)
    {
        printAccessType(proxyInfo.dwAccessType);
        if (proxyInfo.lpszProxy)
        {
            _tprintf(_T("proxy server list: %s\n"), proxyInfo.lpszProxy);
            ::GlobalFree((HGLOBAL)proxyInfo.lpszProxy);
        }
        if (proxyInfo.lpszProxyBypass)
        {
            _tprintf(_T("proxy bypass list: %s\n"), proxyInfo.lpszProxyBypass);
            ::GlobalFree((HGLOBAL)proxyInfo.lpszProxyBypass);
        }
    }
    if (!::WinHttpCloseHandle(hInet))
    {
        _tprintf(_T("Could not close the handle. WinHttpCloseHandle() failed with %d.\n"), GetLastError());
        CSimpleBuf<TCHAR> errStr = CLoadLibrary::formatMessage<TCHAR>(winhttp.getHandle(), GetLastError());
        _tprintf(_T("\t%s\n"), errStr.Buffer());
    }
    return 0;
}
