/* t4_network.c -- tries to open a TCP connection; should be SUSPICIOUS */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("[t4] socket() failed: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(80);
    inet_pton(AF_INET, "93.184.216.34", &addr.sin_addr); /* example.com */

    int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0) {
        printf("[t4] connect() failed: %s\n", strerror(errno));
    } else {
        printf("[t4] connected to example.com:80\n");
    }
    close(fd);
    return 0;
}

