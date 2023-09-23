#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"
// myheader.h : network packet's header structure

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // 1. ETHERNET
    struct ethheader *eth = (struct ethheader *)packet;
    printf("ETHERNET HEADER\n");
    printf("    src MAC: ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x ", eth->ether_shost[i]);
    }
    printf("\n  dst MAC: ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x ", eth->ether_dhost[i]);
    }

    // 2. IP PACKET (0X0800)
    if (ntohs(eth->ether_type) == 0x0800)
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("IP HEADER\n");
        printf("    scr IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("    dst IP: %s\n", inet_ntoa(ip->iph_destip));

        // 3.  TCP PROTOCOL
        int ip_header_len = ip->iph_ihl * 4;
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
        if (ip->iph_protocol == IPPROTO_TCP)
        {
            printf("TCP HEADER\n");
            printf("    scr TCP: %s\n", ntohs(tcp->tcp_sport));
            printf("    dst TCP: %s\n", ntohs(tcp->tcp_dport));

            return;
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; // sniffing 대상 : tcp packet
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}
