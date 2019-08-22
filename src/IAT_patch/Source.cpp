#include "IATHOOK.h"

int MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

int main() {
	IATHOOK hook(GetModuleHandle(NULL), (char*)"USER32.dll", (char*)"MessageBoxA", MyMessageBoxA);
	if (hook.PatchIAT()) {
		MessageBoxA(NULL, "test", "test", MB_OK);
		if (hook.RestoreIAT()) {
			MessageBoxA(NULL, "test", "test", MB_OK);
		}
	}
	return 0;
}

int MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	return MessageBoxW(NULL, L"hooked message", L"", MB_OK);
}