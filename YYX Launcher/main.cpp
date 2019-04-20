#include <cstdio>
#include <Windows.h>
#include <winternl.h>
#include <processthreadsapi.h>

wchar_t DEFAULT_LAUNCH_PATH[] = L"C:\\Program Files (x86)\\Onmyoji\\Launch.exe";

const ULONG SE_DEBUG_PRIVILEGE = 20L;
typedef NTSTATUS(__stdcall *RtlAdjustPrivilegeT)(
	ULONG    Privilege,
	BOOLEAN  Enable,
	BOOLEAN  CurrentThread,
	PBOOLEAN Enabled
	);

struct RemoteData {
	DWORD magic;
	DWORD virtual_protect_addr;
	DWORD target_addr;
	DWORD sleep_addr;
};

typedef BOOL (__stdcall *VirtualProtectT)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

typedef void (__stdcall *SleepT)(
	DWORD dwMilliseconds
);

void* CodeStartAddr = NULL;
DWORD CodeSize = 0;
__declspec(naked) void InitInjectCode() {
	__asm {
		mov eax, offset end;
		sub eax, offset start;
		mov CodeSize, eax;
		mov CodeStartAddr, offset start;
		ret;

	start:	//ÒÔÏÂ´úÂë»á±»Ð´Èë½ø³Ì
		//prolog
		push esi;
		mov esi, [esp + 8]
		push ebp;
		push ebx;
		push ecx;
		mov ebp, esp;
		sub esp, __LOCAL_SIZE;
	}

	{
		RemoteData* remoteDataAddr = 0;

		__asm mov remoteDataAddr, esi;

		if (remoteDataAddr->magic == 0x1128) {
			VirtualProtectT virtual_protect = (VirtualProtectT)remoteDataAddr->virtual_protect_addr;
			SleepT sleep = (SleepT)remoteDataAddr->sleep_addr;
			DWORD target = remoteDataAddr->target_addr;
			DWORD old_protect = 0;
			DWORD *old_protect_addr = &old_protect;

			__asm {
				/*
				push 0x10000;
				mov eax, sleep;
				call eax;
				*/

				push old_protect_addr;
				push PAGE_EXECUTE_READWRITE;
				push 8;
				push target;
				mov eax, virtual_protect;
				call eax;

				mov eax, target;
				mov dword ptr [eax], 0x000000B8;
				mov dword ptr [eax + 4], 0x0008C200;

				push old_protect_addr;
				push old_protect;
				push 8;
				push target;
				mov eax, virtual_protect;
				call eax;
			}
		}
	}

	__asm {
		//epilog
		mov esp, ebp;
		pop ecx;
		pop ebx;
		pop ebp;
		pop esi;
		ret 4;
	end:
	}
}

int CALLBACK WinMain(
	HINSTANCE   hInstance,
	HINSTANCE   hPrevInstance,
	LPSTR       lpCmdLine,
	int         nCmdShow
) {
	wchar_t dir[MAX_PATH] = { 0 };
	GetModuleFileName(hInstance, (LPWCH)dir, MAX_PATH);
	wchar_t *filename = wcsrchr(dir, L'\\');
	*filename = 0;

	wchar_t ini_path[MAX_PATH] = { 0 };
	wcscpy_s(ini_path, dir);
	wcscat_s(ini_path, L"\\yyx-launcher.ini");

	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	BOOLEAN enabled;
	RtlAdjustPrivilegeT RtlAdjustPrivilege = (RtlAdjustPrivilegeT)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	if (!NT_SUCCESS(RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, 1, 0, &enabled))) {
		MessageBox(NULL, L"ÇëÊ¹ÓÃ¹ÜÀíÔ±È¨ÏÞÆô±¾³ÌÐò¡£", L"Ñ÷Ñ÷ÐÜÆô¶¯Æ÷", MB_ICONERROR);
		return -1;
	}
	HMODULE kernel32 = GetModuleHandle(L"Kernel32.dll");
	DWORD process32first_addr = (DWORD)GetProcAddress(kernel32, "Process32First");
	DWORD virtual_protect_addr = (DWORD)GetProcAddress(kernel32, "VirtualProtect");

	STARTUPINFO startup_info = { 0 };
	PROCESS_INFORMATION process_info = { 0 };
	BOOL ok;
	
	while (true) {
		wchar_t yys_launch_path[MAX_PATH] = { 0 };
		ok = GetPrivateProfileString(L"YYXLaucher", L"YYSLaunchPath", DEFAULT_LAUNCH_PATH, yys_launch_path, MAX_PATH, ini_path);
		if (!ok) {
			MessageBox(NULL, L"¶ÁÈ¡ÅäÖÃÎÄ¼þÊ§°Ü¡£", L"Ñ÷Ñ÷ÐÜÆô¶¯Æ÷", MB_ICONERROR);
			return -1;
		}

		ok = CreateProcess(
			NULL,
			yys_launch_path,
			NULL,
			NULL,
			0,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&startup_info,
			&process_info
		);
		if (!ok) {
			auto last_error = GetLastError();
			if (last_error == ERROR_FILE_NOT_FOUND) {
				OPENFILENAME ofn = { 0 };
				wchar_t file_path[MAX_PATH] = { 0 };
				ofn.lStructSize = sizeof(ofn);
				ofn.lpstrFile = file_path;
				ofn.nMaxFile = sizeof(file_path);
				ofn.lpstrFilter = L"ÒõÑôÊ¦ Launch.exe\0Launch.exe";
				ofn.nFilterIndex = 1;
				ofn.lpstrFileTitle = NULL;
				ofn.nMaxFileTitle = 0;
				ofn.lpstrInitialDir = NULL;
				ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
				ofn.lpstrTitle = L"ÇëÖ¸¶¨ÒõÑôÊ¦Launch.exeµÄÂ·¾¶";
				if (GetOpenFileName(&ofn)) {
					ok = WritePrivateProfileString(L"YYXLaucher", L"YYSLaunchPath", file_path, ini_path);
					if (!ok) {
						wchar_t msg[255] = { 0 };
						_snwprintf_s(msg, 255, L"±£´æÅäÖÃÊ§°Ü: WRITE INI %u", GetLastError());
						MessageBox(NULL, msg, L"Ñ÷Ñ÷ÐÜÆô¶¯Æ÷", MB_ICONERROR);
						return -1;
					}
				}
				else {
					return 0;
				}
				continue;
			}

			wchar_t msg[255] = { 0 };
			_snwprintf_s(msg, 255, L"Æô¶¯Ñ÷Ñ÷ÊóÊ§°Ü: CREATE %u", GetLastError());
			MessageBox(NULL, msg, L"Ñ÷Ñ÷ÐÜÆô¶¯Æ÷", MB_ICONERROR);
			return -1;
		}
		else {
			break;
		}
	}

	InitInjectCode();

	RemoteData remote_data = { 0 };
	remote_data.magic = 0x1128;
	remote_data.target_addr = process32first_addr;
	remote_data.virtual_protect_addr = virtual_protect_addr;
	remote_data.sleep_addr = (DWORD)GetProcAddress(kernel32, "Sleep");;

	auto mem = VirtualAllocEx(process_info.hProcess, NULL, sizeof(remote_data) + CodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!mem) {
		wchar_t msg[255] = { 0 };
		_snwprintf_s(msg, 255, L"Æô¶¯Ñ÷Ñ÷ÊóÊ§°Ü: ALLOC %u", GetLastError());
		MessageBox(NULL, msg, L"Ñ÷Ñ÷ÐÜÆô¶¯Æ÷", MB_ICONERROR);
		TerminateProcess(process_info.hProcess, 0);
		return -1;
	}

	ok = WriteProcessMemory(process_info.hProcess, mem, &remote_data, sizeof(RemoteData), NULL);
	if (!ok) {
		wchar_t msg[255] = { 0 };
		_snwprintf_s(msg, 255, L"Æô¶¯Ñ÷Ñ÷ÊóÊ§°Ü: WRITE 1 %u", GetLastError());
		MessageBox(NULL, msg, L"Ñ÷Ñ÷ÐÜÆô¶¯Æ÷", MB_ICONERROR);
		TerminateProcess(process_info.hProcess, 0);
		return -1;
	}

	LPVOID remote_code_addr = (LPVOID)((DWORD)mem + sizeof(RemoteData));

	ok = WriteProcessMemory(process_info.hProcess, remote_code_addr, CodeStartAddr, CodeSize, NULL);
	if (!ok) {
		wchar_t msg[255] = { 0 };
		_snwprintf_s(msg, 255, L"Æô¶¯Ñ÷Ñ÷ÊóÊ§°Ü: WRITE 2 %u", GetLastError());
		MessageBox(NULL, msg, L"Ñ÷Ñ÷ÐÜÆô¶¯Æ÷", MB_ICONERROR);
		TerminateProcess(process_info.hProcess, 0);
		return -1;
	}

	DWORD dw_ok = QueueUserAPC((PAPCFUNC)remote_code_addr, process_info.hThread, (ULONG_PTR)mem);
	if (!ok) {
		wchar_t msg[255] = { 0 };
		_snwprintf_s(msg, 255, L"Æô¶¯Ñ÷Ñ÷ÊóÊ§°Ü: QUEUE %u", GetLastError());
		MessageBox(NULL, msg, L"Ñ÷Ñ÷ÐÜÆô¶¯Æ÷", MB_ICONERROR);
		TerminateProcess(process_info.hProcess, 0);
		return -1;
	}

	ResumeThread(process_info.hThread);

	// printf("addr = 0x%x\n", remote_code_addr);

	//TerminateProcess(process_info.hProcess, 0);
	return 0;
}