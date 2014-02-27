#include <Windows.h>
#include <Winternl.h>
#include <Shlwapi.h> 
#include <tchar.h>

#include "resource.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

#define DRV_NAME					L"YOBA_ETO_TI"
#define DRV_LINK_PATH               L"\\\\.\\YOBA_ETO_TIDLL"
#define FROST_HIDE				    0x9C402408 
#define FROST_UNHIDE			    0x9C402444
#define SystemModuleInformation		11
#define BUFSIZE                     128 * 1024
#define STOP_TIMEOUT				5000
