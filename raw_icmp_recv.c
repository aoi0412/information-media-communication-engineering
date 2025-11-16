#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int main(void) {
    int sockfd;
    unsigned char buf[2048];

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    printf("Waiting for ICMP packets... (run ping in another terminal)\n");

    for (;;) {
        ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            break;
        }

        if ((size_t)n < sizeof(struct ip)) {
            fprintf(stderr, "packet too short: %zd bytes\n", n);
            continue;
        }

        struct ip *iph = (struct ip *)buf;
        unsigned int iphdrlen = iph->ip_hl * 4;
        unsigned short total_len = ntohs(iph->ip_len);

        printf("=== received packet ===\n");
        printf("recv_len           = %zd\n", n);
        printf("ip_header_len      = %u\n", iphdrlen);
        printf("ip_total_length    = %u\n", total_len);
        printf("raw[2:4]           = 0x%02x 0x%02x\n", buf[2], buf[3]);
        printf("protocol           = %u\n", iph->ip_p);

        if (iph->ip_p == IPPROTO_ICMP) {
            printf("ICMP payload bytes (first 16):");
            for (int i = iphdrlen; i < iphdrlen + 16 && i < n; i++) {
                printf(" %02x", buf[i]);
            }
            printf("\n");
        }

        printf("\n");
        fflush(stdout);
    }

    close(sockfd);
    return 0;
}

