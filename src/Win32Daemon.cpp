/**
 * Copyright (C) 2022, The PurpleBote Team
 *
 * This file is part of pboted and licensed under BSD3
 *
 * See full license text in LICENSE file at top of project tree
 */

#ifdef _WIN32 // Windows-only

#ifndef UNICODE
#define UNICODE
#endif

#include <signal.h>
#include <thread>

#include <windows.h>
#include <shellapi.h>

#include "BoteContext.h"
#include "BoteDaemon.h"
#include "DHTworker.h"
#include "Logging.h"
#include "version.h"

#include "win32/Resource.h"
#include "win32/Service.h"

/// Windows Service block

class Service : public WindowsService {
  using WindowsService::WindowsService;

protected:
  virtual DWORD WINAPI worker(LPVOID)
  {
    Daemon.run();
    return ERROR_SUCCESS;
  }
  virtual void on_startup()
  {
    Daemon.start();
  }
  virtual void on_shutdown()
  {
    Daemon.stop();
  }
  virtual void on_stop()
  {
    Daemon.running = false;
  }
};

/**
 * @brief Returns the Win32 error in string format. Returns an empty string if there is no error.
 * Originally posted on https://stackoverflow.com/a/17387176
 *
 * ToDo: move to util namespace
 *
 * @param err error code taken from GetLastError()
 * @return wide string containing error in string format
*/
std::wstring GetLastErrorAsString(DWORD err)
{
    if(err == 0) {
        return std::wstring(); // No error message has been recorded
    }

    LPWSTR messageBuffer = nullptr;

    /// Ask Win32 to give us the string version of that message ID.
    /// The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

    /// Copy the error message into a std::string.
    std::wstring message(messageBuffer, size);

    /// Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}

void SignalHandler(int sig)
{
  switch (sig)
    {
      case SIGINT:
      case SIGABRT:
      case SIGTERM:
        LogPrint(eLogWarning, "Daemon: received signal ", sig);
        Daemon.running = false;
        break;
      default:
        LogPrint(eLogWarning, "Daemon: Unknown signal received: ", sig);
        break;
    }
}

/// Windows WinAPI Tray UI block

UINT const WMAPP_NOTIFYCALLBACK = WM_APP + 1;

wchar_t const szWindowClass[] = L"pbotedDaemon";

void                RegisterWindowClass(PCWSTR pszClassName, PCWSTR pszMenuName, WNDPROC lpfnWndProc);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
void                ShowContextMenu(HWND hwnd, POINT pt);
BOOL                AddNotificationIcon(HWND hwnd);
BOOL                DeleteNotificationIcon(HWND hwnd);

WCHAR               szTitle[100];

void RegisterWindowClass(PCWSTR pszClassName, PCWSTR pszMenuName, WNDPROC lpfnWndProc)
{
    WNDCLASSEX wcex;
    memset (&wcex, 0, sizeof (wcex));
    wcex.cbSize         = sizeof(wcex);
    wcex.style          = 0;
    wcex.lpfnWndProc    = lpfnWndProc;
    wcex.hInstance      = Daemon.m_hInstance;
    wcex.hIcon          = LoadIcon (Daemon.m_hInstance, MAKEINTRESOURCE(IDI_PBOTEDICON));
    wcex.hCursor        = LoadCursor (NULL, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName   = pszMenuName;
    wcex.lpszClassName  = pszClassName;

    if (!RegisterClassEx (&wcex))
    {
      std::wstringstream ErrMsg;
      ErrMsg << L"Failed to register window class " << szWindowClass <<": " << GetLastErrorAsString(GetLastError()) << std::endl;
      MessageBox(NULL, ErrMsg.str ().c_str (), szTitle, MB_ICONERROR | MB_OK | MB_TOPMOST);
    }
}

BOOL AddNotificationIcon(HWND hwnd)
{
    NOTIFYICONDATA nid;
    memset(&nid, 0, sizeof(nid));
    nid.hWnd             = hwnd;
    nid.uID              = IDS_PBOTEDICON;
    nid.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_SHOWTIP;
    nid.uCallbackMessage = WMAPP_NOTIFYCALLBACK;
    nid.hIcon            = LoadIcon (Daemon.m_hInstance, MAKEINTRESOURCE(IDI_PBOTEDICON));

    LoadString(Daemon.m_hInstance, IDS_TOOLTIP, nid.szTip, ARRAYSIZE(nid.szTip));
    Shell_NotifyIcon(NIM_ADD, &nid);

    // NOTIFYICON_VERSION_4 is prefered
    nid.uVersion = NOTIFYICON_VERSION_4;
    return Shell_NotifyIcon(NIM_SETVERSION, &nid);
}

BOOL DeleteNotificationIcon(HWND hwnd)
{
    NOTIFYICONDATA nid;
    memset(&nid, 0, sizeof(nid));
    nid.hWnd            = hwnd;
    nid.uID             = IDS_PBOTEDICON;
    return Shell_NotifyIcon(NIM_DELETE, &nid);
}

void ShowContextMenu(HWND hwnd, POINT pt)
{
  HMENU hMenu = LoadMenu(Daemon.m_hInstance, MAKEINTRESOURCE(IDC_CONTEXTMENU));
    if (hMenu)
    {
        HMENU hSubMenu = GetSubMenu(hMenu, 0);
        if (hSubMenu)
        {
            // our window must be foreground before calling TrackPopupMenu or the menu will not disappear when the user clicks away
            SetForegroundWindow(hwnd);

            // respect menu drop alignment
            UINT uFlags = TPM_RIGHTBUTTON;
            if (GetSystemMetrics(SM_MENUDROPALIGNMENT) != 0)
            {
                uFlags |= TPM_RIGHTALIGN;
            }
            else
            {
                uFlags |= TPM_LEFTALIGN;
            }

            TrackPopupMenuEx(hSubMenu, uFlags, pt.x, pt.y, hwnd, NULL);
        }
        DestroyMenu(hMenu);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  static UINT s_uTaskbarRestart;

  switch (message)
  {
  case WM_CREATE:
    s_uTaskbarRestart = RegisterWindowMessage(TEXT("TaskbarCreated"));
    // add the notification icon
    if (!AddNotificationIcon(hwnd))
    {
      MessageBox(hwnd, L"Unable to start tray application icon", szTitle, MB_OK);
      return -1;
    }
    break;

  case WM_COMMAND:
  {
    int const wmId = LOWORD(wParam);
    // Parse the menu selections:
    switch (wmId)
    {
    case IDM_EXIT:
      DestroyWindow(hwnd);
      break;

    case IDM_ABOUT:
      {
        std::wstringstream text;
        text << "Version: " << PBOTED_VERSION << " " << CODENAME;
        MessageBox(hwnd, text.str ().c_str (), szTitle, MB_ICONINFORMATION | MB_OK );
      }
      break;

    default:
      return DefWindowProc(hwnd, message, wParam, lParam);
    }
  }
  break;

  case WMAPP_NOTIFYCALLBACK:
    switch (LOWORD(lParam))
    {
    case WM_CONTEXTMENU:
      {
        POINT const pt = { LOWORD(wParam), HIWORD(wParam) };
        ShowContextMenu(hwnd, pt);
      }
      break;
    }
    break;

  case WM_DESTROY:
    {
      DeleteNotificationIcon(hwnd);
      PostQuitMessage(0);
    }
    break;

  default:
    if (message == s_uTaskbarRestart)
    {
      AddNotificationIcon(hwnd);
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
  }

  return 0;
}
/// Windows Daemon block

namespace bote
{

bool DaemonWin32::init(int argc, char* argv[])
{
  bool ret = Daemon_Singleton::init(argc, argv);

  LoadString(Daemon.m_hInstance, IDS_APP_TITLE, szTitle, ARRAYSIZE(szTitle));

  if (ret && isDaemon)
  {
    Service pbotedSvc(szTitle, false);
    pbotedSvc.run();
    return EXIT_SUCCESS; // Application terminated, no need to continue it more
  }
  else if (ret)
  {
    bote::log::SetThrowFunction ([](const std::string& s)
    {
      std::wstring ws = std::wstring(s.begin(), s.end());
      const wchar_t* str = ws.c_str();
      MessageBox(0, str, szTitle, MB_ICONERROR | MB_TASKMODAL | MB_OK );
    });
  }
  return ret;
}

int DaemonWin32::start()
{
  RegisterWindowClass(szWindowClass, NULL, WndProc);

  if (FindWindow (szWindowClass, szTitle))
  {
    MessageBox(NULL, L"Application is running already", szTitle, MB_OK);
    return EXIT_FAILURE;
  }

  if (!CreateWindow(szWindowClass, szTitle, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
      CW_USEDEFAULT, 0, 250, 200, NULL, NULL, Daemon.m_hInstance, NULL))
  {
    std::wstringstream ErrMsg;
    ErrMsg << L"Failed to create main window: " << GetLastErrorAsString(GetLastError()) << std::endl;
    MessageBox(NULL, ErrMsg.str ().c_str (), szTitle, MB_ICONERROR | MB_OK | MB_TOPMOST);
    return EXIT_FAILURE;
  }

  signal(SIGINT, SignalHandler);
  signal(SIGABRT, SignalHandler);
  signal(SIGTERM, SignalHandler);

  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);

  return Daemon_Singleton::start();
}

bool DaemonWin32::stop()
{
  if (running)
    running = false;

  HWND hWnd = FindWindow (szWindowClass, szTitle);
  if (hWnd)
    PostMessage (hWnd, WM_COMMAND, MAKEWPARAM(IDM_EXIT, 0), 0);

  return Daemon_Singleton::stop();
}

void DaemonWin32::run()
{
  // Main message loop:
  MSG msg;
  while (running && GetMessage(&msg, NULL, 0, 0))
  {
    /// ToDo: Run network_worker in different thread!
    if (bote::network_worker.is_sick ())
    {
      LogPrint(eLogError, "Daemon: SAM session is sick, try to re-connect");
      bote::network_worker.init ();
      bote::network_worker.start ();
    }

    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
}

} // namespace bote

#endif // _WIN32
