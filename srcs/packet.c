/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/25 12:00:38 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/25 14:31:03 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#define _GNU_SOURCE
#include "packet.h"

#include <assert.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "checksum.h"
#include "ft_nmap.h"
#include "wrapper.h"

static struct iphdr
construct_iphdr(in_addr_t src_ip, in_addr_t dst_ip, uint8_t protocol) {
    struct iphdr iphdr = {0};

    iphdr.saddr    = src_ip;
    iphdr.daddr    = dst_ip;
    iphdr.frag_off = 0;
    iphdr.check    = 0; /* Always filled by the kernel. */
    iphdr.id       = 0; /* Filled by the kernel when equals to 0. */
    iphdr.tot_len  = 0; /* Always filled by the kernel. */
    iphdr.ihl      = 5; /* Header length */
    iphdr.tos      = 0;
    iphdr.ttl      = DFT_TTL;
    iphdr.protocol = protocol;
    iphdr.version  = IPVERSION;

    return (iphdr);
}

uint16_t
get_random_ephemeral_src_port(void) {
    return (rand() % (65535 - 49152 + 1) + 49152);
}

int
send_icmp_echo_request(int sock, in_addr_t src_ip, in_addr_t dst_ip, uint16_t seq) {
    struct iphdr       iphdr    = {0};
    struct icmphdr     icmp     = {0};
    struct sockaddr_in destsock = {0};
    struct timespec    now      = {0};
    uint8_t            packet[IP_MAXPACKET];

    iphdr = construct_iphdr(src_ip, dst_ip, IPPROTO_ICMP);

    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    icmp.type             = ICMP_ECHO;
    icmp.code             = 0;
    icmp.un.echo.id       = (uint16_t)(gettid() & 0xFFFF);
    icmp.un.echo.sequence = seq;
    icmp.checksum         = compute_imcphdr_checksum(icmp, &now, sizeof(now));

    memcpy(packet, &iphdr, sizeof(iphdr));
    memcpy(packet + sizeof(iphdr), &icmp, sizeof(icmp));
    memcpy(packet + sizeof(iphdr) + sizeof(icmp), &now, sizeof(now));
    destsock.sin_addr.s_addr = dst_ip;
    destsock.sin_port        = 0;
    if (Sendto(sock, packet, sizeof(iphdr) + sizeof(icmp) + sizeof(now), 0, (const struct sockaddr *)&destsock, sizeof(destsock)) == -1) {
        return (-1);
    }
}

int
send_tcp_packet(int sock, in_addr_t src_ip, in_port_t src_port, in_addr_t dst_ip, in_port_t dst_port, t_scan_type scan_type) {
    struct iphdr       iphdr    = {0};
    struct tcphdr      tcp      = {0};
    struct sockaddr_in destsock = {0};
    uint8_t            packet[IP_MAXPACKET];

    iphdr = construct_iphdr(src_ip, dst_ip, IPPROTO_TCP);
    switch (scan_type) {
        case STYPE_SYN:
            tcp.syn = 1;
            break;
        case STYPE_NULL:
            break;
        case STYPE_FIN:
            tcp.fin = 1;
            break;
        case STYPE_XMAS:
            tcp.fin = 1;
            tcp.psh = 1;
            tcp.urg = 1;
            break;
        case STYPE_ACK:
            tcp.ack = 1;
            break;
        default:
            assert(0 && "Trying to send a TCP packet with a non-TCP scan type.");
    }

    tcp.source = htons(src_port);
    tcp.dest   = htons(dst_port);
    tcp.window = htons(1024);
    tcp.seq    = rand();
    tcp.doff   = 5;
    tcp.check  = compute_tcphdr_checksum(iphdr.saddr, iphdr.daddr, tcp, NULL, 0);

    memcpy(packet, &iphdr, sizeof(iphdr));
    memcpy(packet + sizeof(iphdr), &tcp, sizeof(tcp));
    destsock.sin_addr.s_addr = dst_ip;
    destsock.sin_port        = dst_port;
    if (Sendto(sock, packet, sizeof(iphdr) + sizeof(tcp), 0, (const struct sockaddr *)&destsock, sizeof(destsock)) == -1) {
        return (-1);
    }

    return (0);
}

int
send_udp_packet(int sock_raw_fd, in_addr_t src_ip, in_port_t src_port, in_addr_t dst_ip, in_port_t dst_port) {
    struct iphdr       iphdr    = {0};
    struct udphdr      udphdr   = {0};
    struct sockaddr_in destsock = {0};
    uint8_t            packet[IP_MAXPACKET];

    udphdr.source = htons(src_port);
    udphdr.dest   = htons(dst_port);
    udphdr.len    = htons(sizeof(udphdr));
    udphdr.check  = compute_udphdr_checksum(iphdr.saddr, iphdr.daddr, udphdr, NULL, 0);

    memcpy(packet, &iphdr, sizeof(iphdr));
    memcpy(packet + sizeof(iphdr), &udphdr, sizeof(udphdr));
    destsock.sin_addr.s_addr = dst_ip;
    destsock.sin_port        = dst_port;
    if (Sendto(sock_raw_fd, packet, sizeof(iphdr) + sizeof(udphdr), 0, (const struct sockaddr *)&destsock, sizeof(destsock)) == -1) {
        return (-1);
    }
    return (0);
}