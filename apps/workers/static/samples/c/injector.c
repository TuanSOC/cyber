/* CyberLab capa fixture: references the remote-process write-and-execute API set.
 *
 * Compiled at test time with mingw-w64 so capa sees real call sites; it is only ever parsed,
 * never run. Even if it were run, the inject() path needs an explicit opt-in argument and the
 * "payload" is a single RET byte.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int inject(DWORD pid, const unsigned char *payload, SIZE_T len) {
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

int main(int argc, char **argv) {
    static const unsigned char payload[] = {0xC3};
    if (argc != 3 || strcmp(argv[1], "--cyberlab-never-run") != 0) {
        puts("CyberLab capa fixture (inert)");
        return 0;
    }
    return inject((DWORD)strtoul(argv[2], NULL, 10), payload, sizeof payload);
}
