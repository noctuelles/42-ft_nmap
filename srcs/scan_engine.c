/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:47:08 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/17 16:49:17 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

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
    tcp.seq    = htonl(create_tcp_token(ip.ip_src.s_addr, tcp.dest, ip.ip_dst.s_addr, tcp.source, key));
    tcp.doff   = 5;

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
    data       = create_tcp_token(ip.ip_src.s_addr, udp.dest, ip.ip_dst.s_addr, udp.source, key);
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

void *
receiver_thread(void *data) {}

void *
transmitter_thread(void *data) {
    t_thread_ctx            *thread_ctx = data;
    const t_scan_queue_data *elem       = NULL;
    size_t                   nsend      = 0;
    int                      fd         = 0;

    if ((fd = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return (NULL);
    }

    pthread_barrier_wait(&barrier);

    while ((elem = scan_queue_dequeue(thread_ctx->scan_queue)) != NULL) {
        if (elem->scan_type >= SYN_SCAN && elem->scan_type <= ACK_SCAN) {
            send_tcp_packet(fd, thread_ctx->local.sin_addr.s_addr, elem->resv_host->sockaddr.sin_addr.s_addr, elem->port, elem->scan_type,
                            thread_ctx->key);
        } else if (elem->scan_type == UDP_SCAN) {
            send_udp_packet(fd, thread_ctx->local.sin_addr.s_addr, elem->resv_host->sockaddr.sin_addr.s_addr, elem->port, thread_ctx->key);
        }
        nsend++;
    }
    return (NULL);
}