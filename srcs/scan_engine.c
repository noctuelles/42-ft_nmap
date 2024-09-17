/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:47:08 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/17 19:07:45 by plouvel          ###   ########.fr       */
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

#include "checksum.h"
#include "hash.h"
#include "queue.h"
#include "wrapper.h"

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

void *
receiver_thread(void *data) {
    t_recv_thread_ctx *ctx      = data;
    pcap_t            *handle   = NULL;
    struct bpf_program bpf_prog = {0};

    if ((handle = Pcap_open_live(ctx->device, IP_MAXPACKET, 1, -1)) == NULL) {
        return (NULL);
    }
    if (Pcap_compile(handle, &bpf_prog, ctx->filter, 0, 0) != 0) {
        return (NULL);
    }
    if (Pcap_setfilter(handle, &bpf_prog) != 0) {
        return (NULL);
    }
    pthread_barrier_wait(ctx->barrier);
    if (pcap_loop(handle, ctx->n_probes, receiver_packet_handler, (u_char *)ctx->key) == PCAP_ERROR) {
        return (NULL);
    }
    return (NULL);
}

void *
sender_thread(void *data) {
    t_send_thread_ctx       *ctx   = data;
    const t_scan_queue_data *elem  = NULL;
    size_t                   nsend = 0;
    int                      fd    = 0;

    if ((fd = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return (NULL);
    }
    pthread_barrier_wait(ctx->barrier);
    while ((elem = scan_queue_dequeue(ctx->scan_queue)) != NULL) {
        if (elem->scan_type >= SYN_SCAN && elem->scan_type <= ACK_SCAN) {
            send_tcp_packet(fd, ctx->local.sin_addr.s_addr, elem->resv_host->sockaddr.sin_addr.s_addr, elem->port, elem->scan_type,
                            ctx->key);
        } else if (elem->scan_type == UDP_SCAN) {
            send_udp_packet(fd, ctx->local.sin_addr.s_addr, elem->resv_host->sockaddr.sin_addr.s_addr, elem->port, ctx->key);
        }
        nsend++;
    }
    return (NULL);
}