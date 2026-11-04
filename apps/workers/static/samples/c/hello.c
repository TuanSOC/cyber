/* CyberLab benign test program: compiled at test time with mingw-w64, parsed, never run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checksum(const char *text) {
    unsigned sum = 0;
    for (size_t i = 0; i < strlen(text); i++) {
        sum = sum * 31u + (unsigned char)text[i];
    }
    return sum;
}

int main(int argc, char **argv) {
    const char *name = argc > 1 ? argv[1] : "world";
    printf("Hello, %s! (CyberLab benign sample)\n", name);
    printf("checksum: %u\n", checksum(name));
    return EXIT_SUCCESS;
}
