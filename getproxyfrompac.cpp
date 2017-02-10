#include "stdafx.h"
#include <winhttp.h>
#include "SimpleBuffer.h"
#ifndef VTRACE
#   define VTRACE(...) while (false) {} /*lint -e506 -e681*/
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

void printLastError(LPCTSTR failedFuncName, HMODULE hMsgFile)
{
    _ftprintf(stderr, _T("ERROR: %s failed with %d.\n"), failedFuncName, GetLastError());
    CSimpleBuf<TCHAR> errStr = CLoadLibrary::formatMessage<TCHAR>(hMsgFile, GetLastError());
    _ftprintf(stderr, _T("\t%s\n"), errStr.Buffer());
}

extern "C" int _tmain(int argc, _TCHAR* argv[])
{
    CSimpleBuf<TCHAR> detectedPacUrl;
    CLoadLibrary winhttp(_T("winhttp.dll"));
    if (argc < 2 || argc > 3)
    {
        _ftprintf(stderr, _T("Syntax:\n\t%s <url> [pac-url]>\n"), argv[0]);
        return __LINE__;
    }
    LPCTSTR lpszUrlToCheck = argv[1];
    LPCTSTR lpszPacUrl = argv[2];
    /* the value for argv[argc] is always NULL, so if no PAC URL is given we can detect it this way */
    if (NULL == lpszPacUrl)
    {
        LPTSTR lpszAutoConfigUrl = NULL;
        if (!::WinHttpDetectAutoProxyConfigUrl(WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A, &lpszAutoConfigUrl))
        {
            printLastError(_T("WinHttpDetectAutoProxyConfigUrl"), winhttp.getHandle());
            _ftprintf(stderr, _T("You can avoid this error by giving an explict PAC file URL.\n"));
            return __LINE__;
        }
        if (lpszAutoConfigUrl)
        {
            detectedPacUrl = lpszAutoConfigUrl;
            lpszPacUrl = detectedPacUrl.Buffer();
            _tprintf(_T("Auto-detected PAC file URL: %s\n"), lpszPacUrl);
        }
        ::GlobalFree((HGLOBAL)lpszAutoConfigUrl);
    }
    HINTERNET hInet = ::WinHttpOpen(_T("User"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (NULL == hInet)
    {
        printLastError(_T("WinHttpOpen"), winhttp.getHandle());
        return __LINE__;
    }
    WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions = { 0 };
    WINHTTP_PROXY_INFO proxyInfo = { 0 };
    autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
    autoProxyOptions.dwAutoDetectFlags = 0 /* the .NET version passed: WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A */;
    autoProxyOptions.lpszAutoConfigUrl = lpszPacUrl;
    BOOL bProceed = ::WinHttpGetProxyForUrl(hInet, lpszUrlToCheck, &autoProxyOptions, &proxyInfo);
    if (!bProceed)
    {
        printLastError(_T("WinHttpGetProxyForUrl"), winhttp.getHandle());
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
        printLastError(_T("WinHttpCloseHandle"), winhttp.getHandle());
    }
    return 0;
}
