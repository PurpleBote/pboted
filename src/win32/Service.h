  /**
   * Windows Service handler
   *
   * Source:
   * https://github.com/kazaamjt/Win32_Service-CPP-Template
   */

  #pragma once
  #include <string>
  #include <iostream>
  #include <Windows.h>

  class WindowsService {
  private:
    std::string name;
    LPWSTR Wname;
    bool canPauseContinue;

    SERVICE_STATUS status;
    SERVICE_STATUS_HANDLE statusHandle;

    HANDLE workerPaused;
    HANDLE workerContinued;

    static void WINAPI service_main();
    static void WINAPI control_handler(DWORD);
    static DWORD WINAPI worker_thread(LPVOID lpParam);

    // Set accepted controls
    void set_acceptedControls(bool _in);

    // Internal start/stop functions
    void startup();
    void exit();
    void on_error();

    // Service controller invoked start/stop functions
    void control_stop();
    void control_pause();
    void control_continue();
    void control_stopOnPause();

  protected:
    HANDLE stopEvent;
    HANDLE pauseEvent;
    HANDLE continueEvent;

    void set_state(DWORD state);
    static WindowsService *instance;
    virtual DWORD WINAPI worker(LPVOID) { return ERROR_SUCCESS; }

    void confirm_pause() {SetEvent(workerPaused);}
    void confirm_continue() {SetEvent(workerContinued);}

    // Functions that get called on specific events
    virtual void on_startup() {};
    virtual void on_pause() {};
    virtual void on_continue() {};
    virtual void on_stop() {};
    virtual void on_exit() {};

    // Run this when we fail to register with the Windows Service Manager
    virtual void on_failedRegistration() { test_startStop(); }

    // Tell the service controller we're still alive during lenghty pending operations. EG STOP_PENDING. Not for during bump.
    void bump();

  public:
    WindowsService(std::string _name, bool _canPauseContinue);
    void test_startStop();
    int run();

  };

  void castWStr(wchar_t* &wsz, const char* sz)
  {
    std::vector<wchar_t> vec;
    size_t len = strlen(sz);
    vec.resize(len+1);
    mbstowcs(&vec[0],sz,len);
    wsz = &vec[0];
  }

  WindowsService *WindowsService::instance;

  WindowsService::WindowsService(std::string _name, bool _canPauseContinue):
    name(_name), canPauseContinue(_canPauseContinue) {
    //Wname = const_cast<wchar_t*>(name.c_str());
    castWStr(Wname, name.c_str());

    //status = { 0 };
    statusHandle = NULL;

    stopEvent = INVALID_HANDLE_VALUE;
    pauseEvent = INVALID_HANDLE_VALUE;
    continueEvent = INVALID_HANDLE_VALUE;
  }

  int WindowsService::run() {
    instance = this;

    SERVICE_TABLE_ENTRY serviceTable[] =
    {
      { Wname, (LPSERVICE_MAIN_FUNCTION)service_main },
    { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(serviceTable) == FALSE) {
      DWORD serviceDispatchError = GetLastError();
      if (serviceDispatchError == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
        on_failedRegistration();
      }
      else {
        return serviceDispatchError;
      }
    }

    return 0;
  }

  void WINAPI WindowsService::service_main() {
    // Register our service control handler with the SCM
    instance->statusHandle = RegisterServiceCtrlHandler(instance->Wname, instance->control_handler);

    if (instance->statusHandle == NULL) {
      return;
    }

    instance->startup();

    // Start a thread that will perform the main task of the service
    HANDLE hThread = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);

    // Wait until our worker thread exits signaling that the service needs to stop
    WaitForSingleObject(hThread, INFINITE);

    instance->exit();
  }

  void WINAPI WindowsService::control_handler(DWORD CtrlCode)
  {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
      if (instance->status.dwCurrentState == SERVICE_PAUSED) {
        instance->control_stopOnPause();
        break;
      }

      if (instance->status.dwCurrentState != SERVICE_RUNNING) { break; }
      instance->control_stop();
      break;

    case SERVICE_CONTROL_PAUSE:
      if (instance->status.dwCurrentState != SERVICE_RUNNING) { break; }
      instance->control_pause();
      break;

    case SERVICE_CONTROL_CONTINUE:
      if (instance->status.dwCurrentState != SERVICE_PAUSED) { break; }
      instance->control_continue();
      break;

    case SERVICE_CONTROL_SHUTDOWN:
      if (instance->status.dwCurrentState != SERVICE_RUNNING) { break; }
      instance->control_stop();
      break;

    case SERVICE_CONTROL_INTERROGATE: // Deprecated, but you never know... let's just handle it.
      SetServiceStatus(instance->statusHandle, &instance->status);
      break;

    default:
      break;
    }
  }

  DWORD WINAPI WindowsService::worker_thread(LPVOID lpParam) {
    return instance->worker(lpParam);
  }

  void WindowsService::startup() {
    ZeroMemory(&status, sizeof(status));
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    set_acceptedControls(false);
    status.dwServiceSpecificExitCode = 0;
    set_state(SERVICE_START_PENDING);

    on_startup();

    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    pauseEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    continueEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (stopEvent == NULL) {
      on_error();
      return;
    }

    set_acceptedControls(true);

    set_state(SERVICE_RUNNING);
  }

  void WindowsService::exit() {
    on_exit();
    CloseHandle(stopEvent);
    CloseHandle(pauseEvent);
    CloseHandle(continueEvent);
    CloseHandle(workerPaused);
    CloseHandle(workerContinued);
    set_state(SERVICE_STOPPED);
  }

  void WindowsService::on_error() {
    set_acceptedControls(false);
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwWin32ExitCode = GetLastError();
    status.dwCheckPoint = 0;

    if (SetServiceStatus(statusHandle, &status) == FALSE)
    {
      LPWSTR MSG;
      std::string debugmsg = name + ": service_main: SetServiceStatus returned an error";
      castWStr(MSG, debugmsg.c_str());
      OutputDebugString(MSG);
    }
  }

  void WindowsService::control_stop() {
    set_state(SERVICE_STOP_PENDING);
    on_stop();
    set_acceptedControls(false);
    SetEvent(stopEvent);
  }

  void WindowsService::control_pause() {
    set_state(SERVICE_PAUSE_PENDING);
    on_pause();
    SetEvent(pauseEvent);
    WaitForSingleObject(workerPaused, INFINITE);
    set_state(SERVICE_PAUSED);
  }

  void WindowsService::control_continue() {
    set_state(SERVICE_CONTINUE_PENDING);
    set_acceptedControls(false);
    ResetEvent(pauseEvent);
    on_continue();
    SetEvent(continueEvent);
    WaitForSingleObject(workerContinued, INFINITE);
    set_acceptedControls(true);
    ResetEvent(continueEvent);
    set_state(SERVICE_RUNNING);
  }

  void WindowsService::control_stopOnPause() {
    set_acceptedControls(false);
    set_state(SERVICE_STOP_PENDING);
    on_continue();
    SetEvent(stopEvent);
    SetEvent(continueEvent);
  }

  void WindowsService::set_state(DWORD state) {
    status.dwCurrentState = state;
    status.dwWin32ExitCode = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    SetServiceStatus(statusHandle, &status);
    if (SetServiceStatus(statusHandle, &status) == FALSE)
    {
      LPWSTR MSG;
      std::string debugmsg = name + ": service_main: SetServiceStatus returned an error";
      castWStr(MSG, debugmsg.c_str());
      OutputDebugString(MSG);
    }
  }

  void WindowsService::set_acceptedControls(bool _in) {
    if (_in) {
      status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
      if (canPauseContinue) {
        status.dwControlsAccepted |= SERVICE_ACCEPT_PAUSE_CONTINUE;
      }
    }
    else {
      status.dwControlsAccepted = 0;
    }

    if (SetServiceStatus(statusHandle, &status) == FALSE)
    {
      LPWSTR MSG;
      std::string debugmsg = name + ": service_main: SetServiceStatus change accepted controls operation failed";
      castWStr(MSG, debugmsg.c_str());
      OutputDebugString(MSG);
    }
  }

  void WindowsService::bump() {
    status.dwCheckPoint++;
    if (SetServiceStatus(statusHandle, &status) == FALSE)
    {
      LPWSTR MSG;
      std::string debugmsg = name + ": service_main: SetServiceStatus dwCheckPoint operation failed";
      castWStr(MSG, debugmsg.c_str());
      OutputDebugString(MSG);
    }
  }

  void WindowsService::test_startStop() {
    std::cout << "START_PENDING" << std::endl;
    on_startup();

    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    pauseEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    continueEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    HANDLE hThread = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
    std::cout << "RUNNING\n" << std::endl;

    std::cout << "Press enter to simulate SCM stop event...";
    std::cin.ignore();

    std::cout << "\nSTOP_PENDING" << std::endl;
    on_stop();
    SetEvent(stopEvent);
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "STOPPED" << std::endl;
  }
