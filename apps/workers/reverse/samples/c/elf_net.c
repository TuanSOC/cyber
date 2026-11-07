/* CyberLab RE fixture: parsed only, never run.
 *
 * Linux (gcc): `socket` / `connect` in one function that references an address from the
 * 192.0.2.0/24 documentation range (phase 5's network-string rule, M10 phase 4). Built PIE
 * and non-PIE (`-no-pie`) so phase 12 checks the capa join on both ELF types (RT8). The
 * connecting path only runs behind the opt-in argument; nothing here is ever executed.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CL_NOINLINE __attribute__((noinline, noclone))

/* re: fn=open_channel
 * re: import=socket, inet_pton, connect, close
 * re: string=192.0.2.10
 * re: finding=heuristic:re_network_string_function@1|network_string_function|low
 */
CL_NOINLINE int open_channel(void) {
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons(8443);
    if (inet_pton(AF_INET, "192.0.2.10", &address.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    int rc = connect(fd, (struct sockaddr *)&address, sizeof address);
    close(fd);
    return rc;
}

/* re: fn=describe
 * re: string=CyberLab ELF network fixture (inert)
 */
CL_NOINLINE const char *describe(void) {
    return "CyberLab ELF network fixture (inert)";
}

/* re: fn=main
 * re: calls=describe, open_channel
 * re: string=--cyberlab-never-run
 */
int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--cyberlab-never-run") != 0) {
        puts(describe());
        return 0;
    }
    return open_channel() == 0 ? 0 : 1;
}
