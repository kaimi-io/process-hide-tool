#include "hidden_run.h"

const char functions[][32] =
{
    "ZwOpenProcess",
    "ZwQuerySystemInformation",
    "ZwReadVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwCreateUserProcess",
    "ZwDuplicateObject"
};

BOOL (WINAPI * IsWow64Process_)(HANDLE, PBOOL);
BOOL (WINAPI * CreateProcessWithTokenW_)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
BOOL load_button_state = FALSE;
HINSTANCE ghInstance;
HWND ghWnd;

void display_error(TCHAR * message)
{
	TCHAR error_message[64];

	swprintf_s(error_message, sizeof(error_message) / sizeof(TCHAR), L"%s - %08X", message, GetLastError());
	MessageBox(ghWnd, error_message, L"Error", MB_OK | MB_ICONERROR);
}

BOOL install_driver(SC_HANDLE sm, TCHAR * name, TCHAR * path)
{
    SC_HANDLE service;

    service = CreateService
    (
        sm, name, name,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        path, NULL, NULL, NULL, NULL, NULL
    );

    if(GetLastError() == ERROR_SERVICE_EXISTS)
        service = OpenService(sm, name, SERVICE_ALL_ACCESS);
    
    if(service == NULL)
        return FALSE;

    if(StartService(service, 0, NULL) == FALSE)
    {
        DeleteService(service);
        return FALSE;
    }

    CloseServiceHandle(service);

    return TRUE;
}

BOOL remove_driver(SC_HANDLE sm, TCHAR * name)
{
    SC_HANDLE service;
	SERVICE_STATUS_PROCESS ssp;
	DWORD bytes, wait_time, start_time;
	BOOL state = TRUE;

	
    service = OpenService(sm, name, SERVICE_ALL_ACCESS);
    if(service == NULL)
        return FALSE;
    
	while(1)
	{
		if(state == FALSE)
		{
			if(service)
				CloseServiceHandle(service);

			return FALSE;
		}
		
		
		if(!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes))
		{
			state = FALSE;
			continue;
		}

		if(ssp.dwCurrentState == SERVICE_STOPPED)
		{
			break;
		}

		start_time = GetTickCount();

		while(ssp.dwCurrentState == SERVICE_STOP_PENDING)
		{
			wait_time = ssp.dwWaitHint / 10;

			if(wait_time < 1000)
				wait_time = 1000;
			else if (wait_time > 10000)
				wait_time = 10000;

			Sleep(wait_time);

			if(!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes))
			{
				state = FALSE;
				break;
			}

			if(ssp.dwCurrentState == SERVICE_STOPPED)
			{
				CloseServiceHandle(service);
				return TRUE;
			}

			if(GetTickCount() - start_time > STOP_TIMEOUT)
			{
				CloseServiceHandle(service);
				state = FALSE;
				display_error(L"Can't unload driver - timeout");
				break;
			}
		}

		if(state == FALSE)
			continue;

		if(!ControlService(service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
		{
			state = FALSE;
			continue;
		}

		while(ssp.dwCurrentState != SERVICE_STOPPED)
		{
			Sleep(ssp.dwWaitHint);

			if(!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes))
			{
				state = FALSE;
				break;
			}

			if(ssp.dwCurrentState == SERVICE_STOPPED)
			{
				CloseServiceHandle(service);
				return TRUE;
			}

			if(GetTickCount() - start_time > STOP_TIMEOUT)
			{
				CloseServiceHandle(service);
				state = FALSE;
				display_error(L"Can't unload driver - timeout");
				break;
			}
		}

		if(state == FALSE)
			continue;
    
		if(!DeleteService(service))
		{
			state = FALSE;
			continue;
		}

		break;
	}

	CloseServiceHandle(service);

	return TRUE;
}

DWORD GetOpenName(TCHAR * outbuf, const TCHAR * filter, const TCHAR * title)
{
    OPENFILENAME ofn;
    TCHAR buf[MAX_PATH + 2];
    TCHAR * tmp;

    ZeroMemory(&ofn, sizeof(OPENFILENAME));
    GetModuleFileName(NULL, buf, MAX_PATH);

    tmp = StrRChr(buf, NULL, L'\\');
    if(tmp != 0)
    {
        *tmp = 0;
        ofn.lpstrInitialDir = buf;
    }

    ofn.hInstance = ghInstance;
    ofn.hwndOwner = ghWnd;
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = outbuf;
    ofn.lpstrFile[0] = 0;
    ofn.lpstrFile[1] = 0;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_EXPLORER | OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST | OFN_LONGNAMES | OFN_NONETWORKBUTTON | OFN_PATHMUSTEXIST;

    return GetOpenFileName(&ofn);
}

DWORD compute_crc(DWORD * buffer)
{
    int i;
    DWORD result = 0;

    for(i = 0; i < 15; i++)
    {
        /* CRC is stored in the third element */
        if(i == 3)
            continue;
        result ^= 0xFF * ((buffer[i] << 16) + (buffer[i] >> 16));
    }

    return result;
}

BOOL fill_buffer(DWORD * buffer, size_t buffer_size)
{
    HMODULE ntdll, kernel32;
    SYSTEM_INFO sys_info;
    FARPROC IsWow64Process_;
    int i;
    DWORD aux;
    void * sys_m_inf;
	NTSTATUS result;

    if(buffer_size < sizeof(DWORD) * 17)
    {
        display_error(L"Erroneous buffer size");
        return FALSE;
    }

    ZeroMemory(buffer, buffer_size);

    buffer[0] = GetCurrentProcessId();

    GetSystemInfo(&sys_info);
	buffer[4] = sys_info.dwPageSize;


    kernel32 = GetModuleHandle(L"kernel32.dll");
    if(kernel32 == NULL)
    {
        display_error(L"Can't get kernel32 handle");
        return FALSE;
    }

    IsWow64Process_ = GetProcAddress(kernel32, "IsWow64Process");
    if(IsWow64Process_)
    {
        if(!IsWow64Process_(GetCurrentProcess(), &i) || i == 0)
        {
            ntdll = GetModuleHandle(L"ntdll.dll");
            if(ntdll == NULL)
            {
                display_error(L"Can't get ntdll handle");
                return FALSE;
            }

            //5-16
            //5-6 7-8
            for(i = 0; i < sizeof(functions) / sizeof(functions[0]); i++)
            {
                aux = (DWORD)GetProcAddress(ntdll, functions[i]);
                buffer[2 * i + 5] = (aux == 0 ? 0 : *(DWORD *)((BYTE *)aux + 1));
                buffer[2 * i + 5 + 1] = 0;
            }
            

            sys_m_inf = VirtualAlloc(NULL, BUFSIZE, MEM_COMMIT, PAGE_READWRITE);
            if(sys_m_inf == NULL)
            {
                display_error(L"Memory allocation error");
                return FALSE;
            }

            result = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, sys_m_inf, BUFSIZE, NULL);
			if(NT_ERROR(result))
			{
				VirtualFree(sys_m_inf, 0, MEM_RELEASE);
				display_error(L"NtQuerySystemInformation error");
				return FALSE;
			}

            buffer[1] = *((DWORD *)sys_m_inf + 3);
	        buffer[2] = *((DWORD *)sys_m_inf + 4) + buffer[1];

            VirtualFree(sys_m_inf, 0, MEM_RELEASE);
        }
    }

    buffer[3] = compute_crc(buffer);

    return TRUE;
}

BOOL hide_unhide(BOOL do_hide, TCHAR * link_path)
{
    DWORD in_buffer[17], out_buffer, aux;
    HANDLE drv;
    
    if(do_hide)
        fill_buffer(in_buffer, sizeof(in_buffer));
    else
        in_buffer[0] = (GetCurrentProcessId() ^ 0x77917F) + 0x29D8;

	
	drv = CreateFile
	(
		link_path != NULL ? link_path : DRV_LINK_PATH,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0
	);

	if(drv == INVALID_HANDLE_VALUE)
    {
        display_error(L"Can't access driver symbolic link");
		return FALSE;
    }

    if
	(
		DeviceIoControl
		(
			drv,
			do_hide ? FROST_HIDE : FROST_UNHIDE,
			in_buffer,
			do_hide ? sizeof(in_buffer) : sizeof(in_buffer[0]),
			&out_buffer,
			sizeof(out_buffer),
			&aux,
			NULL
		) == FALSE
	)
	{
        CloseHandle(drv);
		display_error(L"DeviceIoControl failed");

		return FALSE;
	}

    CloseHandle(drv);


	return TRUE;
}

BOOL create_process(TCHAR * path, BOOL as_user)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    TOKEN_PRIVILEGES tkp;
    DWORD pid, token_rights;
    HWND shell_wnd;
    BOOL state = TRUE;
    HANDLE shell_process = NULL, shell_token = NULL, primary_token = NULL, process_token = NULL;
    HMODULE advapi;
    FARPROC CreateProcessWithTokenW_;

    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    si.cb = sizeof(STARTUPINFO);
    
    if(as_user)
    {
        advapi = GetModuleHandle(L"Advapi32.dll");
        if(advapi == NULL)
        {
            display_error(L"Can't get advapi32 handle");
            return FALSE;
        }
        
        CreateProcessWithTokenW_ = GetProcAddress(advapi, "CreateProcessWithTokenW");
        if(!CreateProcessWithTokenW_)
        {
            display_error(L"Can't get CreateProcessWithTokenW address");
            return FALSE;
        }

        if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &process_token))
        {
            display_error(L"OpenProcessToken failed");
            return FALSE;
        }

        tkp.PrivilegeCount = 1;
        if(!LookupPrivilegeValue(NULL, SE_INCREASE_QUOTA_NAME, &tkp.Privileges[0].Luid))
        {
            CloseHandle(process_token);
            display_error(L"LookupPrivilegeValue failed");
            return FALSE;
        }

        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if(!AdjustTokenPrivileges(process_token, FALSE, &tkp, 0, NULL, NULL) || GetLastError() != ERROR_SUCCESS)
        {
            CloseHandle(process_token);
            display_error(L"AdjustTokenPrivileges failed");
            return FALSE;
        }

        CloseHandle(process_token);


        shell_wnd = GetShellWindow();
        if(shell_wnd == NULL)
        {
            display_error(L"Can't get explorer HWND");
            return FALSE;
        }

        GetWindowThreadProcessId(shell_wnd, &pid);
        if(pid == 0)
        {
            display_error(L"Can't get explorer pid");
            return FALSE;
        }

        shell_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if(shell_process == NULL)
        {
            display_error(L"Can't open explorer process");
            return FALSE;
        }

        while(1)
        {
            if(state == FALSE)
            {
                if(shell_token)
                    CloseHandle(shell_token);
                if(shell_process)
                    CloseHandle(shell_process);
                if(primary_token)
                    CloseHandle(primary_token);

                return FALSE;
            }
            else
            {
                if(!OpenProcessToken(shell_process, TOKEN_DUPLICATE, &shell_token))
                {
                    state = FALSE;
                    display_error(L"Can't open explorer process token");
                    continue;
                }

                token_rights = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

                if(!DuplicateTokenEx(shell_token, token_rights, NULL, SecurityImpersonation, TokenPrimary, &primary_token))
                {
                    state = FALSE;
                    display_error(L"Can't duplicate explorer process token");
                    continue;
                }

                if(!CreateProcessWithTokenW_(primary_token, 0, path, NULL, 0, NULL, NULL, &si, &pi))
                {
                    state = FALSE;
                    display_error(L"CreateProcessWithTokenW_ failed");
                    continue;
                }

                CloseHandle(shell_token);
                CloseHandle(primary_token);
                CloseHandle(shell_process);

                break;
            }
        }
    }
    else
    {
        if(!CreateProcess(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            display_error(L"CreateProcess failed");
            return FALSE;
        }
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

int MainDlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static HICON ico;
	OSVERSIONINFO version;
    TCHAR path[MAX_PATH], symlink[MAX_PATH];
    static SC_HANDLE sm = NULL;
	BOOL checkbox_state;

    switch(uMsg)
    {
        case WM_INITDIALOG:
			ghWnd = hWnd;

			ico = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON));
			SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)ico);

            sm = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, GENERIC_WRITE | GENERIC_EXECUTE);
            if(sm == NULL)
            {
				display_error(L"Can't open service manager");
				DestroyIcon(ico);
                EndDialog(hWnd, 1);
            }


			version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
			if(GetVersionEx(&version))
			{
				if(version.dwMajorVersion < 6)
					EnableWindow(GetDlgItem(hWnd, IDC_RUNAS), FALSE);
			}
			else
				display_error(L"Can't get OS version");

            SendDlgItemMessage(hWnd, IDC_PATH, EM_LIMITTEXT, MAX_PATH, 0);
        break;

        case WM_COMMAND:
            switch(LOWORD(wParam))
            {
                case IDC_START:
					if(GetOpenName(path, TEXT("Executable (*.exe)\0*.exe\0All files (*.*)\0*.*\0\0"), TEXT("Select exectuable to run...")))
					{
						checkbox_state = SendDlgItemMessage(hWnd, IDC_SYM, BM_GETCHECK, 0, 0);
                        
						if(checkbox_state == BST_CHECKED)
						{
							GetDlgItemText(hWnd, IDC_PATH, symlink, MAX_PATH);
							if(hide_unhide(TRUE, symlink) == FALSE)
								break;
						}
						else
							if(hide_unhide(TRUE, NULL) == FALSE)
								break;
						
                        create_process(path, SendDlgItemMessage(hWnd, IDC_RUNAS, BM_GETCHECK, 0, 0) == BST_CHECKED);
						
                        
						if(checkbox_state == BST_CHECKED)
							hide_unhide(FALSE, symlink);
						else
							hide_unhide(FALSE, NULL);
					}
                break;

                case IDC_LOAD:
                    GetDlgItemText(hWnd, IDC_PATH, path, MAX_PATH);
					
                    if(load_button_state)
                    {
                        if(remove_driver(sm, DRV_NAME) == FALSE)
                        {
							display_error(L"Can't unload specified driver");
                            break;
                        }

                        SetDlgItemText(hWnd, IDC_LOAD, TEXT("Load driver"));
                        load_button_state = FALSE;
                    }
                    else
                    {
                        if(install_driver(sm, DRV_NAME, path) == FALSE)
                        {
                            display_error(L"Can't load specified driver");
                            break;
                        }

                        SetDlgItemText(hWnd, IDC_LOAD, TEXT("Unload driver"));
                        load_button_state = TRUE;
                    }
                    
                    EnableWindow(GetDlgItem(hWnd, IDC_START), load_button_state);
                    EnableWindow(GetDlgItem(hWnd, IDC_PATH), !load_button_state);
                    EnableWindow(GetDlgItem(hWnd, IDC_BROWSE), !load_button_state);
                break;

				case IDC_SYM:
					if(SendDlgItemMessage(hWnd, IDC_SYM, BM_GETCHECK, 0, 0) == BST_CHECKED)
					{
						SetDlgItemText(hWnd, IDC_STC1, L"Symlink");
						EnableWindow(GetDlgItem(hWnd, IDC_START), TRUE);
						EnableWindow(GetDlgItem(hWnd, IDC_BROWSE), FALSE);
						EnableWindow(GetDlgItem(hWnd, IDC_LOAD), FALSE);
					}
					else
					{
						SetDlgItemText(hWnd, IDC_STC1, L"Driver path");
						EnableWindow(GetDlgItem(hWnd, IDC_START), load_button_state);
						EnableWindow(GetDlgItem(hWnd, IDC_BROWSE), !load_button_state);
						EnableWindow(GetDlgItem(hWnd, IDC_LOAD), TRUE);
					}
				break;

                case IDC_BROWSE:
                    if(GetOpenName(path, TEXT("Driver (*.sys)\0*.sys\0All files (*.*)\0*.*\0\0"), TEXT("Select driver...")))
                        SetDlgItemText(hWnd, IDC_PATH, path);
                break;
            }
        break;

        case WM_CLOSE:
            if(sm)
            {
                remove_driver(sm, DRV_NAME);
                CloseServiceHandle(sm);
            }
			DestroyIcon(ico);
            EndDialog(hWnd, 0);
        break;

        default:
            return 0;
    }

    return 1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    ghInstance = hInstance;

    DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_MAIN), 0, (DLGPROC) MainDlgProc, 0);
 
    return 0;
}
