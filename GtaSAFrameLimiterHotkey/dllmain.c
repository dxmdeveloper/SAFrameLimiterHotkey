#include <Windows.h>
#include <strsafe.h>

#define DEFAULT_HOTKEY VK_DELETE
const WCHAR pathToIni[] = L"SAFrameLimiterHotkey.ini";

// --- game offsets ---
void *const CGame_GameProccess_CallAddr = (void *const)(0x53E981);
char *const leftTopCornerText = (char *const)(0xBAA7A0);
BYTE *const frameLimiterFlag = (BYTE *const)(0xBA6794);

// --- global variables ---
void(__cdecl *nextCall)() = NULL;

// --- option variables ---
int hotkey1 = DEFAULT_HOTKEY;
int hotkey2 = 0;
BOOL showMessage = FALSE;

// --- function declaration ---
inline void FrameLimiterHotkeyFunc();
void FrameLimiterHotkeyInjectionProxy();
void ReadOptionsFromIni();
void InjectHook();
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);

// --- function definition ---
inline void FrameLimiterHotkeyFunc() {
	static BOOL wasPressed = 0;
	BOOL isPressed = (GetAsyncKeyState(hotkey1) & 0x8000)
		&& (!hotkey2 || (GetAsyncKeyState(hotkey2) & 0x8000));

	if (isPressed && !wasPressed) {
		if (showMessage) {
			lstrcpyA(leftTopCornerText, (*frameLimiterFlag ? "Frame Limiter ~r~OFF~w~" : "Frame Limiter ~g~ON~w~"));
		}
		// Toggle the frame limiter
		*frameLimiterFlag = !*frameLimiterFlag;
	}
	wasPressed = isPressed;
}

void FrameLimiterHotkeyInjectionProxy() {
	FrameLimiterHotkeyFunc();
	nextCall();
}

void ReadOptionsFromIni() {
	// Get the full path to the ini file
	WCHAR fullIniPath[MAX_PATH + 1];
	GetCurrentDirectoryW(MAX_PATH + 1, fullIniPath);
	StringCbCatW(fullIniPath, MAX_PATH + 1, L"\\");
	StringCbCatW(fullIniPath, MAX_PATH + 1, pathToIni);

	// Read the hotkey options
	hotkey1 = GetPrivateProfileIntW(L"options", L"hotkey1", 0, fullIniPath);
	if (!hotkey1) hotkey1 = DEFAULT_HOTKEY;
	hotkey2 = GetPrivateProfileIntW(L"options", L"hotkey2", 0, fullIniPath);

	// Read the show_message option
	WCHAR buf[6] = L"false";
	GetPrivateProfileStringW(L"options", L"show_message", L"false", buf, 6, fullIniPath);
	showMessage = !lstrcmpiW(buf, L"true") || !lstrcmpiW(buf, L"1");
}

void InjectHook()
{
	DWORD callInstOff = (DWORD)CGame_GameProccess_CallAddr;

	// Unprotect the memory
	DWORD oldProtect;
	VirtualProtect(CGame_GameProccess_CallAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	// save the address to make a call chain
	// 5 is the size of the call instruction
	nextCall = (void *)(callInstOff + 5 + *(DWORD *)(callInstOff + 1));

	// Patch the call instruction
	*(DWORD *)(callInstOff + 1) = (DWORD)FrameLimiterHotkeyInjectionProxy - (callInstOff + 5);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		ReadOptionsFromIni();
		InjectHook();
	}
	return TRUE;
}
