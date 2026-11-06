/* CyberLab RE fixture: parsed only, never run.
 *
 * Known import usage per function (import-reference recall and the phase-5 function-level
 * rules, M10 phase 4), Windows only (mingw-w64):
 * - read_settings: file I/O (CreateFileW / ReadFile / CloseHandle);
 * - resolve_by_name: GetModuleHandleA + GetProcAddress with three API-name literals. Inert:
 *   the resolved pointers are stored and never called, and the function itself only runs
 *   behind the opt-in argument below;
 * - remote_write: the M3 process-injection API set in one function (the M3 injector.c body),
 *   guarded by the M3 `--cyberlab-never-run` pattern; the "payload" is a single RET byte.
 * `import=` lists the imports each function calls, `finding=` the phase-5 finding expected
 * there (`method|type|severity`). Compiled at test time, never executed.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CL_NOINLINE __attribute__((noinline, noclone))

static FARPROC g_resolved[3];

/* re: fn=read_settings
 * re: import=CreateFileW, ReadFile, CloseHandle
 * re: string=C:\ProgramData\CyberLab\re-fixture.ini
 */
CL_NOINLINE DWORD read_settings(char *out, DWORD size) {
    HANDLE file = CreateFileW(L"C:\\ProgramData\\CyberLab\\re-fixture.ini", GENERIC_READ,
                              FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD read = 0;
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    if (!ReadFile(file, out, size, &read, NULL)) {
        read = 0;
    }
    CloseHandle(file);
    return read;
}

/* re: fn=resolve_by_name
 * re: import=GetModuleHandleA, GetProcAddress
 * re: string=kernel32.dll
 * re: string=VirtualAllocEx
 * re: string=WriteProcessMemory
 * re: string=CreateRemoteThread
 * re: finding=heuristic:re_runtime_api_resolution@1|runtime_api_resolution|medium
 */
CL_NOINLINE int resolve_by_name(void) {
    HMODULE module = GetModuleHandleA("kernel32.dll");
    if (module == NULL) {
        return 0;
    }
    g_resolved[0] = GetProcAddress(module, "VirtualAllocEx");
    g_resolved[1] = GetProcAddress(module, "WriteProcessMemory");
    g_resolved[2] = GetProcAddress(module, "CreateRemoteThread");
    return g_resolved[0] != NULL && g_resolved[1] != NULL && g_resolved[2] != NULL;
}

/* re: fn=remote_write
 * re: import=OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, WaitForSingleObject, CloseHandle
 * re: finding=heuristic:re_api_set_function@1|api_injection|medium
 */
CL_NOINLINE int remote_write(DWORD pid, const unsigned char *payload, SIZE_T len) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process == NULL) {
        return 1;
    }
    LPVOID remote = VirtualAllocEx(process, NULL, len, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (remote == NULL) {
        CloseHandle(process);
        return 2;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, payload, len, &written)) {
        CloseHandle(process);
        return 3;
    }
    HANDLE thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL,
                                       0, NULL);
    if (thread != NULL) {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
    CloseHandle(process);
    return 0;
}

/* re: fn=main
 * re: calls=read_settings, resolve_by_name, remote_write
 * re: string=--cyberlab-never-run
 * re: string=CyberLab RE imports fixture (inert)
 */
int main(int argc, char **argv) {
    static const unsigned char payload[] = {0xC3};
    char settings[128];
    if (argc != 3 || strcmp(argv[1], "--cyberlab-never-run") != 0) {
        puts("CyberLab RE imports fixture (inert)");
        return read_settings(settings, sizeof settings) > 0 ? 0 : 1;
    }
    if (!resolve_by_name()) {
        return 4;
    }
    return remote_write((DWORD)strtoul(argv[2], NULL, 10), payload, sizeof payload);
}
