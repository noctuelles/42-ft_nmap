/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:47:08 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 19:08:05 by plouvel          ###   ########.fr       */
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
#include <sys/select.h>
#include <unistd.h>

#include "checksum.h"
#include "logger.h"
#include "queue.h"
#include "wrapper.h"

#define MAX_RETRIES 3
#define FILTER_TCP "dst host %s and (icmp or ((tcp) and (src host %s) and (src port %u) and (dst port %u)))"
#define FILTER_MAX_SIZE (1 << 10)

static int             g_thread_ok = 0;
static int             g_thread_ko = -1;
static pthread_mutex_t g_rslt_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_rslt_idx  = 0;

typedef struct s_loop_ctx {
    int            fd;
    pcap_t        *pcap_hdl;
    in_port_t      dst_port;
    in_port_t      src_port;
    struct in_addr dst_ip;
    struct in_addr src_ip;
    uint32_t       seq_nbr;
} t_loop_ctx;

static int
send_tcp_packet(int sock_raw_fd, in_addr_t src_ip, in_port_t src_port, in_addr_t dest_ip, in_port_t dest_port, t_scan_type scan_type) {
    struct ip          ip       = {0};
    struct tcphdr      tcp      = {0};
    struct sockaddr_in destsock = {0};
    uint8_t            packet[IP_MAXPACKET];

    ip.ip_src.s_addr = src_ip;
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

    switch (scan_type) {
        case SYN:
            tcp.syn = 1;
            break;
        case NUL:
            break;
        case FIN:
            tcp.fin = 1;
            break;
        case XMAS:
            tcp.fin = 1;
            tcp.psh = 1;
            tcp.urg = 1;
            break;
        case ACK:
            tcp.ack = 1;
            break;
        default:
            assert(0 && "Trying to send a TCP packet with a non-TCP scan type.");
    }

    tcp.source = htons(src_port);
    tcp.dest   = htons(dest_port);
    tcp.window = htons(1024);
    tcp.seq    = rand();
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

// static int
// send_udp_packet(int sock_raw_fd, in_addr_t local_ip, in_addr_t dest_ip, in_port_t dest_port, const char key[16]) {
//     struct ip          ip       = {0};
//     struct udphdr      udp      = {0};
//     struct sockaddr_in destsock = {0};
//     uint32_t           data     = 0;
//     uint8_t            packet[IP_MAXPACKET];

//     ip.ip_src.s_addr = local_ip;
//     ip.ip_dst.s_addr = dest_ip;
//     ip.ip_off        = 0;
//     ip.ip_sum        = 0; /* Always filled by the kernel. */
//     ip.ip_len        = 0; /* Always filled by the kernel. */
//     ip.ip_id         = 0; /* Filled by the kernel when equals to 0. */
//     ip.ip_hl         = 5; /* Header length */
//     ip.ip_tos        = 0;
//     ip.ip_ttl        = 64;
//     ip.ip_p          = IPPROTO_UDP;
//     ip.ip_v          = IPVERSION;

//     const uint16_t ephemeral_port_start = 49152;
//     const uint16_t ephemeral_port_end   = 65535;

//     udp.source = htons(rand() % (ephemeral_port_end - ephemeral_port_start + 1) + ephemeral_port_start);
//     udp.dest   = htons(dest_port);
//     udp.len    = htons(sizeof(udp) + sizeof(data));
//     data       = get_syn_cookie(ip.ip_src.s_addr, udp.dest, ip.ip_dst.s_addr, udp.source,
//                                 key);  // NOT very sure of this one. The syn-cookie method doesn't work (i think) for UDP.
//     udp.check  = compute_udphdr_checksum(ip.ip_src.s_addr, ip.ip_dst.s_addr, udp, &data, sizeof(data));

//     memcpy(packet, &ip, sizeof(ip));
//     memcpy(packet + sizeof(ip), &udp, sizeof(udp));
//     memcpy(packet + sizeof(ip) + sizeof(udp), &data, sizeof(data));

//     destsock.sin_addr.s_addr = dest_ip;
//     destsock.sin_port        = dest_port;
//     if (Sendto(sock_raw_fd, packet, sizeof(ip) + sizeof(udp) + sizeof(data), 0, (const struct sockaddr *)&destsock, sizeof(destsock)) ==
//         -1) {
//         return (-1);
//     }
//     return (0);
// }

static uint16_t
get_random_ephemeral_src_port(void) {
    return (rand() % (65535 - 49152 + 1) + 49152);
}

static int
receive_packet(pcap_t *pcap_hdl, t_scan_rslt *scan_rslt) {
    struct pcap_pkthdr *pkthdr;
    const u_char       *pkt;
    struct ip          *ip     = NULL;
    struct tcphdr      *tcphdr = NULL;

    if (pcap_next_ex(pcap_hdl, &pkthdr, &pkt) != 1) {
        return (-1);
    }

    ip = (struct ip *)(pkt + sizeof(struct ethhdr));

    size_t ip_hdrlen = ip->ip_hl << 2;

    if (ip_hdrlen < sizeof(struct ip)) {
        fprintf(stderr, "Invalid IP header length: %lu\n", ip_hdrlen);
        return (-1);
    }

    tcphdr = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + ip_hdrlen);

    if (tcphdr->syn && tcphdr->ack) {
        scan_rslt->status = OPEN;
    } else if (tcphdr->rst) {
        scan_rslt->status = CLOSED;
    }

    /* */

    return (0);
}

/**
 * @brief
 *
 * @param ctx
 * @param scan_rslt
 * @return int
 *
 * @note The retry strategy is raw and unoptimized. It basically wait
 */
static int
loop(const t_loop_ctx *ctx, t_scan_rslt *scan_rslt) {
    int            pcap_fd = 0;
    fd_set         rfds;
    size_t         try_so_far = 0;
    int            ret_val    = 0;
    struct timeval timeout;

    if ((pcap_fd = pcap_get_selectable_fd(ctx->pcap_hdl)) == -1) {
        return (-1);
    }
    FD_ZERO(&rfds);
    while (try_so_far < MAX_RETRIES) {
        timeout.tv_sec  = 0;
        timeout.tv_usec = 200000;
        FD_SET(pcap_fd, &rfds);

        send_tcp_packet(ctx->fd, ctx->src_ip.s_addr, ctx->src_port, ctx->dst_ip.s_addr, ctx->dst_port, SYN);
        try_so_far++;

        if ((ret_val = select(pcap_fd + 1, &rfds, NULL, NULL, &timeout)) == -1) {
            return (-1);
        } else if (ret_val) {
            if (receive_packet(ctx->pcap_hdl, scan_rslt) != 0) {
                return (-1);
            }
            break;
        }
    }

    scan_rslt->status = FILTERED; /* In Syn Scan */

    return (0);
}

void *
thread_routine(void *data) {
    t_thread_ctx            *ctx = data;
    t_loop_ctx               loop_ctx;
    t_scan_rslt              scan_rslt;
    char                     filter[FILTER_MAX_SIZE];                              /* Filter string */
    char                     p_dst_ip[INET_ADDRSTRLEN], p_src_ip[INET_ADDRSTRLEN]; /* Source and Destination IP Presentation*/
    const t_scan_queue_data *elem = NULL;                                          /* Current scan element */
    struct bpf_program       bpf_prog;
    int                     *ret_val = &g_thread_ko;

    if ((loop_ctx.fd = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return (&g_thread_ko);
    }
    if ((loop_ctx.pcap_hdl = Pcap_create(ctx->device)) == NULL) {
        goto clean_fd;
    }
    if (pcap_set_snaplen(loop_ctx.pcap_hdl, IP_MAXPACKET) != 0) {
        goto clean_pcap;
    }
    if (pcap_setnonblock(loop_ctx.pcap_hdl, 1, NULL) != 0) {
        goto clean_pcap;
    }
    if (pcap_set_promisc(loop_ctx.pcap_hdl, 1) != 0) {
        goto clean_pcap;
    }
    if (Pcap_activate(loop_ctx.pcap_hdl) != 0) {
        goto clean_pcap;
    }
    loop_ctx.src_ip = ctx->local.sin_addr;
    pthread_barrier_wait(ctx->sync_barrier);
    loop_ctx.src_port = get_random_ephemeral_src_port();
    while ((elem = scan_queue_dequeue(ctx->scan_queue)) != NULL) {
        loop_ctx.dst_ip   = elem->resv_host->sockaddr.sin_addr;
        loop_ctx.dst_port = elem->port;

        scan_rslt.resv_host = elem->resv_host;
        scan_rslt.port      = loop_ctx.dst_port;
        scan_rslt.status    = UNDETERMINED;
        scan_rslt.type      = SYN;

        inet_ntop(AF_INET, &loop_ctx.src_ip, p_src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &loop_ctx.dst_ip, p_dst_ip, INET_ADDRSTRLEN);

        (void)snprintf(filter, sizeof(filter), FILTER_TCP, p_src_ip, p_dst_ip, loop_ctx.dst_port, loop_ctx.src_port);

        if (Pcap_compile(loop_ctx.pcap_hdl, &bpf_prog, filter, 0, 0) != 0) {
            goto clean_pcap;
        }
        if (Pcap_setfilter(loop_ctx.pcap_hdl, &bpf_prog) != 0) {
            goto clean_bpf_prog;
        }
        pcap_freecode(&bpf_prog);

        if (loop(&loop_ctx, &scan_rslt) != 0) {
            goto clean_pcap;
        }

        pthread_mutex_lock(&g_rslt_lock);
        ctx->scan_rslts[g_rslt_idx++] = scan_rslt;
        pthread_mutex_unlock(&g_rslt_lock);
    }
    ret_val = &g_thread_ok;
clean_bpf_prog:
    pcap_freecode(&bpf_prog);
clean_pcap:
    pcap_close(loop_ctx.pcap_hdl);
clean_fd:
    (void)close(loop_ctx.fd);
    return (ret_val);
}