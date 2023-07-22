#include <string.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "pcap-test.h"

void print_mac(u_int8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_ip(struct in_addr addr) {
    u_int8_t m[4];
    memcpy(m, &addr, sizeof(struct in_addr));
    printf("%u.%u.%u.%u", m[0], m[1], m[2], m[3]);
}

void print_tcp(u_int16_t port) {
    printf(":%u", ntohs(port));
}

void print_payload(const u_char *payload) {
    for (int i = 0; i < 10; i++) {
        printf("%02x", payload[i]);
		if (i < 9) {
			printf("|");
			if ((i + 1) % 10 == 0)
				printf("\n");
			}
	}
    printf("\n");
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
		printf("\n");
        print_mac(eth_hdr->ether_shost);
        printf(" -> ");
        print_mac(eth_hdr->ether_dhost);

        if (ntohs(eth_hdr->ether_type) == 0x0800) {
            struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

            if (ip_hdr->ip_p == 6) {
                struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)((u_char*)ip_hdr + (ip_hdr->ip_vhl & 0x0F) * 4);

                printf(", ");
                print_ip(ip_hdr->ip_src);
                print_tcp(tcp_hdr->th_sport);
                printf(" -> ");
                print_ip(ip_hdr->ip_dst);
                print_tcp(tcp_hdr->th_dport);

                const u_char* tcp_payload = (const u_char*)tcp_hdr + TH_OFF(tcp_hdr) * 4;
				printf(", ");
                print_payload(tcp_payload);
            } else {continue;}
        } else {continue;}
    }

    pcap_close(pcap);
}

