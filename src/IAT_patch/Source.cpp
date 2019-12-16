#include "cIATHook.h"

int MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

int main() {
	cIATHook hook((char*)"user32.dll", (char*)"MessageBoxA", MyMessageBoxA);
	MessageBoxA(NULL, "test", "test", MB_OK);
	if (hook.RestoreIAT()) {
		MessageBoxA(NULL, "test", "test", MB_OK);
	}
	return 0;

}

int MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	return MessageBoxW(NULL, L"hooked message", L"", MB_OK);
}
