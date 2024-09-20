/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:47:08 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/20 18:15:19 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <assert.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
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

#define FILTER_ICMP_COND                                                                                                                \
    "icmp[0] == 3 and (icmp[1] == 0 or icmp[1] == 2 or icmp[1] == 3 or icmp[1] == 9 or icmp[1] == 10 or icmp[1] == 13) and icmp[8] == " \
    "0x45"
#define FILTER_TCP_COND "tcp and (src host %s) and (src port %u) and (dst port %u)"
#define FILTER_TCP "dst host %s and ((" FILTER_ICMP_COND ") or (" FILTER_TCP_COND "))"
#define FILTER_MAX_SIZE (1 << 10)

const char *g_available_scan_types[NBR_AVAILABLE_SCANS] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP"};

static int g_thread_ok = 0;
static int g_thread_ko = -1;

static pthread_mutex_t g_rslt_lock = PTHREAD_MUTEX_INITIALIZER; /* This mutex is used to lock the scan results array. */
static int             g_rslt_idx  = 0;

typedef struct s_scan_ctx {
    int                sending_sock;
    pcap_t            *pcap_hdl; /* Pcap handle that we use to sniff packets on. */
    struct sockaddr_in src;
    struct sockaddr_in dst;
    t_scan_type        type;
} t_scan_ctx;

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
receive_packet(const u_char *pkt, t_scan_type scan_type, t_port_status *port_status) {
    struct ip      *ip      = NULL;
    struct tcphdr  *tcphdr  = NULL;
    struct icmphdr *icmphdr = NULL;

    ip = (struct ip *)(pkt + sizeof(struct ethhdr));

    size_t ip_hdrlen = ip->ip_hl << 2;

    if (ip_hdrlen < sizeof(struct ip)) {
        return (-1);
    }

    if (ip->ip_p == IPPROTO_TCP) {
        tcphdr = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + ip_hdrlen);

        switch (scan_type) {
            case STYPE_SYN:
                if (tcphdr->syn && tcphdr->ack) {
                    *port_status = OPEN;
                } else if (tcphdr->rst) {
                    *port_status = CLOSED;
                }
                break;
            case STYPE_NULL:
            case STYPE_FIN:
            case STYPE_XMAS:
                if (tcphdr->rst) {
                    *port_status = CLOSED;
                }
                break;
            case STYPE_ACK:
                if (tcphdr->rst) {
                    *port_status = UNFILTERED;
                }
                break;
            default:
                /* Never happen. */
                *port_status = UNDETERMINED;
        }
    } else if (ip->ip_p == IPPROTO_ICMP) {
        /* TODO */
        tcphdr = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + ip_hdrlen + sizeof(struct icmphdr));
    }

    return (0);
}

/**
 * @brief This loop
 *
 * @param ctx
 * @param scan_rslt
 * @return int
 *
 * @note The retry strategy is raw and unoptimized. It basically wait
 */
static int
scan_port(t_scan_ctx *scan_ctx, t_port_status *port_status) {
    int                 pcap_fd = 0;
    fd_set              rfds;
    size_t              try_so_far = 0;
    int                 ret_val    = 0;
    struct pcap_pkthdr *pkthdr;
    const u_char       *pkt;
    struct timeval      timeout;
    char                filter[FILTER_MAX_SIZE];                              /* Filter string */
    char                p_dst_ip[INET_ADDRSTRLEN], p_src_ip[INET_ADDRSTRLEN]; /* Source and Destination IP Presentation*/
    struct bpf_program  bpf_prog;

    if ((pcap_fd = pcap_get_selectable_fd(scan_ctx->pcap_hdl)) == -1) {
        return (-1);
    }
    FD_ZERO(&rfds);
    while (try_so_far < MAX_RETRIES) {
        if (try_so_far != 0) {
            scan_ctx->src.sin_port += 1;
        }

        /* Build the filter */
        inet_ntop(AF_INET, &scan_ctx->src.sin_addr, p_src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &scan_ctx->dst.sin_addr, p_dst_ip, INET_ADDRSTRLEN);
        (void)snprintf(filter, sizeof(filter), FILTER_TCP, p_src_ip, p_dst_ip, scan_ctx->dst.sin_port, scan_ctx->src.sin_port);
        if (Pcap_compile(scan_ctx->pcap_hdl, &bpf_prog, filter, 0, 0) != 0) {
            return (-1);
        }
        if (Pcap_setfilter(scan_ctx->pcap_hdl, &bpf_prog) != 0) {
            return (-1);
        }
        pcap_freecode(&bpf_prog);

        if (scan_ctx->type >= STYPE_SYN && scan_ctx->type <= STYPE_ACK) {
            send_tcp_packet(scan_ctx->sending_sock, scan_ctx->src.sin_addr.s_addr, scan_ctx->src.sin_port, scan_ctx->dst.sin_addr.s_addr,
                            scan_ctx->dst.sin_port, scan_ctx->type);
        } else if (scan_ctx->type == STYPE_UDP) {
            assert(0 && "UDP Not implemented yet");
        }

        try_so_far++;

    reload:
        timeout.tv_sec  = 0;
        timeout.tv_usec = 300000;
        FD_SET(pcap_fd, &rfds);
        if ((ret_val = select(pcap_fd + 1, &rfds, NULL, NULL, &timeout)) == -1) {
            return (-1);
        } else if (ret_val) {
            if ((ret_val = pcap_next_ex(scan_ctx->pcap_hdl, &pkthdr, &pkt)) == PCAP_ERROR) {
                return (-1);
            } else if (ret_val == 1) {
                receive_packet(pkt, scan_ctx->type, port_status);
                break;
            } else if (ret_val == 0) {
                goto reload;
            } else {
                return (-1);
            }
        }
    }

    /* At this point, if the port status is UNDETERMINED, it means that we didn't receive any response to our probe even after
     * retransmissions. */
    if (*port_status == UNDETERMINED) {
        switch (scan_ctx->type) {
            case STYPE_SYN:
                *port_status = FILTERED;
                break;
            case STYPE_NULL:
            case STYPE_FIN:
            case STYPE_XMAS:
                *port_status = OPEN | FILTERED;
                break;
            case STYPE_ACK:
                *port_status = FILTERED;
            case STYPE_UDP:
                *port_status = OPEN | FILTERED;
        }
    }

    return (0);
}

void *
thread_routine(void *data) {
    t_thread_ctx            *thread_ctx = data;
    t_scan_ctx               scan_ctx;
    t_port_status            port_status;
    const t_scan_queue_data *to_scan = NULL; /* Current scan element */
    int                     *ret_val = &g_thread_ko;

    if ((scan_ctx.sending_sock = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return (&g_thread_ko);
    }
    if ((scan_ctx.pcap_hdl = Pcap_create(thread_ctx->device)) == NULL) {
        goto clean_fd;
    }
    if (pcap_set_snaplen(scan_ctx.pcap_hdl, IP_MAXPACKET) != 0) {
        goto clean_pcap;
    }
    if (pcap_set_immediate_mode(scan_ctx.pcap_hdl, 1) != 0) {
        goto clean_pcap;
    }
    if (pcap_set_timeout(scan_ctx.pcap_hdl, 500) != 0) {
        goto clean_pcap;
    }
    if (pcap_setnonblock(scan_ctx.pcap_hdl, 1, NULL) != 0) {
        goto clean_pcap;
    }
    if (pcap_set_promisc(scan_ctx.pcap_hdl, 1) != 0) {
        goto clean_pcap;
    }
    if (Pcap_activate(scan_ctx.pcap_hdl) != 0) {
        goto clean_pcap;
    }

    pthread_barrier_wait(thread_ctx->sync_barrier);

    scan_ctx.src.sin_addr = thread_ctx->local.sin_addr;
    scan_ctx.src.sin_port = get_random_ephemeral_src_port();
    while ((to_scan = scan_queue_dequeue(thread_ctx->scan_queue)) != NULL) {
        scan_ctx.dst.sin_addr = to_scan->resv_host->sockaddr.sin_addr;
        scan_ctx.dst.sin_port = to_scan->port;

        for (t_scan_type scan_type = 0; scan_type < NBR_AVAILABLE_SCANS; scan_type++) {
            if (thread_ctx->scans_to_perform[scan_type]) {
                scan_ctx.type = scan_type;

                if (scan_port(&scan_ctx, &port_status) != 0) {
                    goto clean_pcap;
                }

                pthread_mutex_lock(&g_rslt_lock);
                thread_ctx->scan_rslts[g_rslt_idx].resv_host = to_scan->resv_host;
                thread_ctx->scan_rslts[g_rslt_idx].port      = to_scan->port;
                thread_ctx->scan_rslts[g_rslt_idx].type      = scan_type;
                thread_ctx->scan_rslts[g_rslt_idx].status    = port_status;
                g_rslt_idx++;
                pthread_mutex_unlock(&g_rslt_lock);
            }
        }
    }

    ret_val = &g_thread_ok;
clean_pcap:
    pcap_close(scan_ctx.pcap_hdl);
clean_fd:
    (void)close(scan_ctx.sending_sock);
    return (ret_val);
}