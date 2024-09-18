/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:47:08 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 11:17:22 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <assert.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "checksum.h"
#include "hash.h"
#include "queue.h"
#include "wrapper.h"

#define FILTER_TCP "dst host %s and (icmp or ((tcp) and (src host %s) and (src port %u) and (dst port %u)))"
#define FILTER_MAX_SIZE (1 << 10)

static int
send_tcp_packet(int sock_raw_fd, in_addr_t local_ip, in_addr_t dest_ip, in_port_t dest_port, t_scan_type scan_type, const char key[16]) {
    struct ip          ip       = {0};
    struct tcphdr      tcp      = {0};
    struct sockaddr_in destsock = {0};
    uint8_t            packet[IP_MAXPACKET];

    ip.ip_src.s_addr = local_ip;
    ip.ip_dst.s_addr = dest_ip;
    ip.ip_off        = 0;
    ip.ip_sum        = 0; /* Always filled by the kernel. */
    ip.ip_len        = 0; /* Always filled by the kernel. */
    ip.ip_id         = 0; /* Filled by the kernel when equals to 0. */
    ip.ip_hl         = 5; /* Header length */
    ip.ip_tos        = 0;
    ip.ip_ttl        = 64;
    ip.ip_p          = IPPROTO_TCP;
    ip.ip_v          = IPVERSION;

    const uint16_t ephemeral_port_start = 49152;
    const uint16_t ephemeral_port_end   = 65535;

    switch (scan_type) {
        case SYN_SCAN:
            tcp.syn = 1;
            break;
        case NULL_SCAN:
            break;
        case FIN_SCAN:
            tcp.fin = 1;
            break;
        case XMAS_SCAN:
            tcp.fin = 1;
            tcp.psh = 1;
            tcp.urg = 1;
            break;
        case ACK_SCAN:
            tcp.ack = 1;
            break;
        default:
            assert(0 && "Trying to send a TCP packet with a non-TCP scan type.");
    }

    tcp.source = htons(rand() % (ephemeral_port_end - ephemeral_port_start + 1) + ephemeral_port_start);
    tcp.dest   = htons(dest_port);
    tcp.window = htons(1024);
    /* This is a SYN-cookie use to see if a response is indeed a response to our probe. */
    tcp.seq  = htonl(get_syn_cookie(ip.ip_dst.s_addr, tcp.dest, ip.ip_src.s_addr, tcp.source, key));
    tcp.doff = 5;

    tcp.check = compute_tcphdr_checksum(ip.ip_src.s_addr, ip.ip_dst.s_addr, tcp, NULL, 0);
    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

    destsock.sin_addr.s_addr = dest_ip;
    destsock.sin_port        = dest_port;
    if (Sendto(sock_raw_fd, packet, sizeof(ip) + sizeof(tcp), 0, (const struct sockaddr *)&destsock, sizeof(destsock)) == -1) {
        return (-1);
    }
    return (0);
}

static int
send_udp_packet(int sock_raw_fd, in_addr_t local_ip, in_addr_t dest_ip, in_port_t dest_port, const char key[16]) {
    struct ip          ip       = {0};
    struct udphdr      udp      = {0};
    struct sockaddr_in destsock = {0};
    uint32_t           data     = 0;
    uint8_t            packet[IP_MAXPACKET];

    ip.ip_src.s_addr = local_ip;
    ip.ip_dst.s_addr = dest_ip;
    ip.ip_off        = 0;
    ip.ip_sum        = 0; /* Always filled by the kernel. */
    ip.ip_len        = 0; /* Always filled by the kernel. */
    ip.ip_id         = 0; /* Filled by the kernel when equals to 0. */
    ip.ip_hl         = 5; /* Header length */
    ip.ip_tos        = 0;
    ip.ip_ttl        = 64;
    ip.ip_p          = IPPROTO_UDP;
    ip.ip_v          = IPVERSION;

    const uint16_t ephemeral_port_start = 49152;
    const uint16_t ephemeral_port_end   = 65535;

    udp.source = htons(rand() % (ephemeral_port_end - ephemeral_port_start + 1) + ephemeral_port_start);
    udp.dest   = htons(dest_port);
    udp.len    = htons(sizeof(udp) + sizeof(data));
    data       = get_syn_cookie(ip.ip_src.s_addr, udp.dest, ip.ip_dst.s_addr, udp.source,
                                key);  // NOT very sure of this one. The syn-cookie method doesn't work (i think) for UDP.
    udp.check  = compute_udphdr_checksum(ip.ip_src.s_addr, ip.ip_dst.s_addr, udp, &data, sizeof(data));

    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &udp, sizeof(udp));
    memcpy(packet + sizeof(ip) + sizeof(udp), &data, sizeof(data));

    destsock.sin_addr.s_addr = dest_ip;
    destsock.sin_port        = dest_port;
    if (Sendto(sock_raw_fd, packet, sizeof(ip) + sizeof(udp) + sizeof(data), 0, (const struct sockaddr *)&destsock, sizeof(destsock)) ==
        -1) {
        return (-1);
    }
    return (0);
}

uint16_t
get_random_ephemeral_src_port(void) {
    return (rand() % (65535 - 49152 + 1) + 49152);
}

static void
receiver_packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user;
    (void)pkthdr;
    (void)packet;

    // struct ethhdr *ethhdr     = NULL;
    struct ip     *ip         = NULL;
    struct tcphdr *tcphdr     = NULL;
    uint32_t       syn_cookie = 0;
    const char    *key        = (const char *)user;

    // ethhdr = (struct ethhdr *)packet;

    /* Do we have to check if the packet is big enough to accomodate everything ? */

    puts("** RECEIVED PACKET **\n");

    // printf("Ethernet type: %x\n", ntohs(ethhdr->h_proto));
    // printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2],
    //        ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5]);
    // printf("Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n\n", ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2],
    //        ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5]);

    ip = (struct ip *)(packet + sizeof(struct ethhdr));

    size_t ip_hdrlen = ip->ip_hl << 2;

    if (ip_hdrlen < sizeof(struct ip)) {
        fprintf(stderr, "Invalid IP header length: %lu\n", ip_hdrlen);
        return;
    }

    tcphdr = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_hdrlen);

    syn_cookie = get_syn_cookie(ip->ip_src.s_addr, tcphdr->source, ip->ip_dst.s_addr, tcphdr->dest, key);

    if (ntohl(tcphdr->ack_seq) - 1 != syn_cookie) {
        printf("TCP cookie doesn't match: %u != %u\n", ntohl(tcphdr->ack_seq) - 1, syn_cookie);
        return;
    } else {
        printf("TCP cookie match: %u == %u\n", ntohl(tcphdr->ack_seq) - 1, syn_cookie);
    }

    printf("TCP Flags: ");
    if (tcphdr->syn) {
        printf("SYN ");
    }
    if (tcphdr->ack) {
        printf("ACK ");
    }
    if (tcphdr->fin) {
        printf("FIN ");
    }
    if (tcphdr->rst) {
        printf("RST ");
    }
    if (tcphdr->psh) {
        printf("PSH ");
    }
    if (tcphdr->urg) {
        printf("URG ");
    }
    printf("\n");
}

static int g_thread_ok = 0;
static int g_thread_ko = -1;

void *
sender_thread(void *data) {
    t_thread_ctx            *ctx         = data;
    const t_scan_queue_data *elem        = NULL;
    int                      raw_sock_fd = 0;
    pcap_t                  *pcap_handle = NULL;
    char                     filter[FILTER_MAX_SIZE], ip_dst[INET_ADDRSTRLEN], ip_src[INET_ADDRSTRLEN];
    struct bpf_program       bpf_prog;
    int                     *ret_val = &g_thread_ko;
    uint16_t                 dst_port, src_port;

    if ((raw_sock_fd = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return (&g_thread_ko);
    }
    if ((pcap_handle = Pcap_create(ctx->device)) == NULL) {
        goto clean_fd;
    }
    (void)pcap_set_snaplen(pcap_handle, IP_MAXPACKET);
    (void)pcap_set_timeout(pcap_handle, 100);
    (void)pcap_set_promisc(pcap_handle, 1);
    if (Pcap_activate(pcap_handle) != 0) {
        goto clean_pcap;
    }
    src_port = get_random_ephemeral_src_port();
    while ((elem = scan_queue_dequeue(ctx->scan_queue)) != NULL) {
        dst_port = elem->port;

        inet_ntop(AF_INET, &ctx->local.sin_addr, ip_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &elem->resv_host->sockaddr.sin_addr, ip_dst, INET_ADDRSTRLEN);

        (void)snprintf(filter, sizeof(filter), FILTER_TCP, ip_src, ip_dst, dst_port, src_port);

        if (Pcap_compile(pcap_handle, &bpf_prog, filter, 0, 0) != 0) {
            goto clean_pcap;
        }
        if (Pcap_setfilter(pcap_handle, &bpf_prog) != 0) {
            goto clean_pcap;
        }
        pcap_freecode(&bpf_prog);
        /* Now we can send the packet and listen ! */
    }
    ret_val = &g_thread_ok;
clean_pcap:
    pcap_close(pcap_handle);
clean_fd:
    (void)close(raw_sock_fd);
    return (ret_val);
}