/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:47:08 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/21 23:28:33 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "scan_engine.h"

#include <assert.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "checksum.h"
#include "queue.h"
#include "wrapper.h"

#define FILTER_ICMP_COND "icmp"
#define FILTER_TCP_COND "tcp and (src host %s) and (src port %u) and (dst port %u)"
#define FILTER_UDP_COND "udp and (src host %s) and (src port %u) and (dst port %u)"

#define FILTER_TCP "dst host %s and ((" FILTER_ICMP_COND ") or (" FILTER_TCP_COND "))"
#define FILTER_UDP "dst host %s and ((" FILTER_ICMP_COND ") or (" FILTER_UDP_COND "))"

#define FILTER_MAX_SIZE (1 << 10)

const char *g_available_scan_types[NBR_AVAILABLE_SCANS] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP"};

static int g_thread_ok = 0;
static int g_thread_ko = -1;

typedef struct s_scan_ctx {
    int                sending_sock;
    pcap_t            *pcap_hdl; /* Pcap handle that we use to sniff packets on. */
    struct sockaddr_in src;
    struct sockaddr_in src_netmask;
    struct sockaddr_in dst;
    t_scan_type        type;
    t_port_status      port_status;
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

static int
send_udp_packet(int sock_raw_fd, in_addr_t src_ip, in_port_t src_port, in_addr_t dest_ip, in_port_t dest_port) {
    struct ip          ip       = {0};
    struct udphdr      udp      = {0};
    struct sockaddr_in destsock = {0};
    uint8_t            packet[IP_MAXPACKET];

    ip.ip_src.s_addr = src_ip;
    ip.ip_dst.s_addr = src_port;
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

    udp.source = htons(src_port);
    udp.dest   = htons(dest_port);
    udp.len    = htons(sizeof(udp));
    udp.check  = compute_udphdr_checksum(ip.ip_src.s_addr, ip.ip_dst.s_addr, udp, NULL, 0);

    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + sizeof(ip), &udp, sizeof(udp));

    destsock.sin_addr.s_addr = dest_ip;
    destsock.sin_port        = dest_port;
    if (Sendto(sock_raw_fd, packet, sizeof(ip) + sizeof(udp), 0, (const struct sockaddr *)&destsock, sizeof(destsock)) == -1) {
        return (-1);
    }
    return (0);
}

static uint16_t
get_random_ephemeral_src_port(void) {
    return (rand() % (65535 - 49152 + 1) + 49152);
}

/**
 * @brief This routine is executed every time a packet is returned by pcap.
 *
 * @param pkt The packet raw content provided by pcap.
 * @param pkthdr The packet header of the pcap capture.
 * @param scan_type Type of ongoing scan.
 * @param port_status Value-result argument.
 * @return int 0 if the packet is the result of one of our probe, -1 is the packet is not relevant: this is not a fatal error.
 */
static int
process_packet(t_scan_ctx *scan_ctx, const u_char *pkt, const struct pcap_pkthdr *pkthdr) {
    size_t                ip_hdrlen = 0;
    const struct ip      *iphdr     = NULL;
    const struct tcphdr  *tcphdr    = NULL;
    const struct icmphdr *icmphdr   = NULL;

    /* Used for ICMP */
    size_t         orig_ip_hdrlen = 0;
    struct ip     *orig_iphdr     = NULL;
    struct tcphdr *orig_tcphdr    = NULL;
    struct udphdr *orig_udphdr    = NULL;

    iphdr = (struct ip *)(pkt + sizeof(struct ethhdr));

    ip_hdrlen = iphdr->ip_hl << 2;

    if (ip_hdrlen < sizeof(struct ip)) {
        return (-1);
    }

    if (iphdr->ip_p == IPPROTO_TCP) {
        tcphdr = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + ip_hdrlen);

        switch (scan_ctx->type) {
            case STYPE_SYN:
                if (tcphdr->syn && tcphdr->ack) {
                    scan_ctx->port_status = OPEN;
                } else if (tcphdr->rst) {
                    scan_ctx->port_status = CLOSED;
                }
                break;
            case STYPE_NULL:
            case STYPE_FIN:
            case STYPE_XMAS:
                if (tcphdr->rst) {
                    scan_ctx->port_status = CLOSED;
                }
                break;
            case STYPE_ACK:
                if (tcphdr->rst) {
                    scan_ctx->port_status = UNFILTERED;
                }
                break;
            default:
                scan_ctx->port_status = UNDETERMINED;
        }
    } else if (iphdr->ip_p == IPPROTO_ICMP) {
        icmphdr    = (struct icmphdr *)(pkt + sizeof(struct ethhdr) + ip_hdrlen);
        orig_iphdr = (struct ip *)((u_char *)(icmphdr) + sizeof(struct icmphdr));

        orig_ip_hdrlen = orig_iphdr->ip_hl << 2;

        if (orig_ip_hdrlen < sizeof(struct ip)) {
            return (-1);
        }
        if (orig_iphdr->ip_src.s_addr != scan_ctx->src.sin_addr.s_addr || orig_iphdr->ip_dst.s_addr != scan_ctx->dst.sin_addr.s_addr) {
            return (-1);
        }
        if (IS_TCP_SCAN(scan_ctx->type)) {
            if (orig_iphdr->ip_p != IPPROTO_TCP) {
                return (-1);
            }

            orig_tcphdr = (struct tcphdr *)((u_char *)orig_iphdr + orig_ip_hdrlen);

            if (htons(orig_tcphdr->source) != scan_ctx->src.sin_port || htons(orig_tcphdr->dest) != scan_ctx->dst.sin_port) {
                return (-1);
            }
        } else if (IS_UDP_SCAN(scan_ctx->type)) {
            if (orig_iphdr->ip_p != IPPROTO_UDP) {
                return (-1);
            }

            orig_udphdr = (struct udphdr *)((u_char *)orig_iphdr + orig_ip_hdrlen);

            if (htons(orig_udphdr->source) != scan_ctx->src.sin_port || htons(orig_udphdr->dest) != scan_ctx->dst.sin_port) {
                return (-1);
            }
        }

        if (icmphdr->type == ICMP_DEST_UNREACH) {
            if (icmphdr->code == ICMP_PORT_UNREACH) {
                if (IS_UDP_SCAN(scan_ctx->type)) {
                    scan_ctx->port_status = CLOSED;
                }
            }

            if (icmphdr->code == ICMP_HOST_UNREACH || icmphdr->code == ICMP_PROT_UNREACH || icmphdr->code == ICMP_PORT_UNREACH ||
                icmphdr->code == ICMP_NET_ANO || icmphdr->code == ICMP_HOST_ANO || icmphdr->code == ICMP_PKT_FILTERED) {
                scan_ctx->port_status = FILTERED;
            } else {
                return (-1);
            }
        } else {
            return (-1);
        }
    } else if (iphdr->ip_p == IPPROTO_UDP) {
        switch (scan_ctx->type) {
            case STYPE_UDP:
                scan_ctx->port_status = OPEN;
                break;
            default:
                scan_ctx->port_status = UNDETERMINED;
        }
    }

    return (0);
}

/**
 * @brief Apply a filter to the pcap handle before sending the probe.
 *
 * @param scan_ctx The scan context.
 * @return int 0 on success, -1 on error.
 */
static int
apply_pcap_filter(t_scan_ctx *scan_ctx) {
    char               presentation_dst_ip[INET_ADDRSTRLEN];
    char               presentation_src_ip[INET_ADDRSTRLEN];
    char               filter[FILTER_MAX_SIZE];
    struct bpf_program bpf_prog;
    int                ret_val = -1;

    (void)inet_ntop(AF_INET, &scan_ctx->src.sin_addr, presentation_src_ip, sizeof(presentation_src_ip));
    (void)inet_ntop(AF_INET, &scan_ctx->dst.sin_addr, presentation_dst_ip, sizeof(presentation_dst_ip));

    if (IS_TCP_SCAN(scan_ctx->type)) {
        (void)snprintf(filter, sizeof(filter), FILTER_TCP, presentation_src_ip, presentation_dst_ip, scan_ctx->dst.sin_port,
                       scan_ctx->src.sin_port);
    } else if (IS_UDP_SCAN(scan_ctx->type)) {
        (void)snprintf(filter, sizeof(filter), FILTER_UDP, presentation_src_ip, presentation_dst_ip, scan_ctx->dst.sin_port,
                       scan_ctx->src.sin_port);
    }
    if (pcap_compile(scan_ctx->pcap_hdl, &bpf_prog, filter, 0, scan_ctx->src_netmask.sin_addr.s_addr) == PCAP_ERROR) {
        goto clean;
    }
    if (pcap_setfilter(scan_ctx->pcap_hdl, &bpf_prog) != 0) {
        goto clean;
    }
    ret_val = 0;
clean:
    pcap_freecode(&bpf_prog);
    return (ret_val);
}

/**
 * @brief For a given scan context, try to conclude the status of the port by sending probes and waiting for an adequate response.
 *
 * @param ctx The scan context.
 * @return int 0 on success, -1 on error.
 *
 */
static int
scan_port(t_scan_ctx *scan_ctx) {
    struct pcap_pkthdr *pkthdr     = NULL;
    const u_char       *pkt        = NULL;
    size_t              try_so_far = 0;
    int                 ret_val    = 0;
    struct pollfd       pollfd     = {0};

    pollfd.events = POLLIN;
    if ((pollfd.fd = pcap_get_selectable_fd(scan_ctx->pcap_hdl)) == -1) {
        return (-1);
    }

    /**
     * Event loop. We send the probe and wait for a response. If we don't receive any response under a specific timeframe, we
     * retransmit the probe.
     */
    while (try_so_far < MAX_RETRIES) {
        if (try_so_far != 0) {
            scan_ctx->src.sin_port += 1;
        }
        if (apply_pcap_filter(scan_ctx) != 0) {
            return (-1);
        }
        if (IS_TCP_SCAN(scan_ctx->type)) {
            if (send_tcp_packet(scan_ctx->sending_sock, scan_ctx->src.sin_addr.s_addr, scan_ctx->src.sin_port,
                                scan_ctx->dst.sin_addr.s_addr, scan_ctx->dst.sin_port, scan_ctx->type) == -1) {
                return (-1);
            }
        } else if (IS_UDP_SCAN(scan_ctx->type)) {
            if (send_udp_packet(scan_ctx->sending_sock, scan_ctx->src.sin_addr.s_addr, scan_ctx->src.sin_port,
                                scan_ctx->dst.sin_addr.s_addr, scan_ctx->dst.sin_port) == -1) {
                return (-1);
            }
        }
        try_so_far++;

    arm_poll:
        if ((ret_val = poll(&pollfd, 1, RETRY_DELAY)) == -1) {
            return (-1);
        } else if (ret_val == 0) {
            continue; /* A timeout occured; send the probe again. */
        } else if (ret_val == 1 && pollfd.revents & POLLIN) {
            if ((ret_val = pcap_next_ex(scan_ctx->pcap_hdl, &pkthdr, &pkt)) == 1) {
                if (process_packet(scan_ctx, pkt, pkthdr) != 0) {
                    goto arm_poll;
                } else {
                    break; /* A valid response was sent to our probe. */
                }
            } else if (ret_val == 0) {
                /* Can happen even if poll notified us that there is data to read : this condition happens when they're is a lot of
                 * concurrent threads. In this case, we re-arm poll. */
                goto arm_poll;
            } else {
                return (-1);
            }
        }
    }

    /* At this point, if the port status is UNDETERMINED, it means that we didn't receive any response to our probe even after
     * retransmissions. */
    if (scan_ctx->port_status == UNDETERMINED) {
        switch (scan_ctx->type) {
            case STYPE_SYN:
                scan_ctx->port_status = FILTERED;
                break;
            case STYPE_NULL:
            case STYPE_FIN:
            case STYPE_XMAS:
                scan_ctx->port_status = OPEN | FILTERED;
                break;
            case STYPE_ACK:
                scan_ctx->port_status = FILTERED;
            case STYPE_UDP:
                scan_ctx->port_status = OPEN | FILTERED;
        }
    }

    return (0);
}

static void
insert_port_status_into_results(const t_resv_host *host, t_scan_rslt *scan_rslts, size_t nbr_hosts, in_port_t port, t_scan_type scan_type,
                                t_port_status port_status) {
    t_scan_rslt *scan_rslt = NULL;

    for (size_t i = 0; i < nbr_hosts; i++) {
        if (scan_rslts[i].host == host) {
            scan_rslt = &scan_rslts[i];
            break;
        }
    }

    scan_rslt->ports[port][scan_type] = port_status;
}

void *
thread_routine(void *data) {
    t_thread_ctx            *thread_ctx     = data;
    t_scan_rslt             *host_scan_rslt = NULL;
    t_scan_ctx               scan_ctx       = {0};
    const t_scan_queue_data *to_scan        = NULL; /* Current scan element */
    int                     *ret_val        = &g_thread_ko;

    if ((scan_ctx.sending_sock = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return (&g_thread_ko);
    }
    if ((scan_ctx.pcap_hdl = Pcap_create(thread_ctx->device)) == NULL) {
        goto clean_fd;
    }
    if (pcap_set_snaplen(scan_ctx.pcap_hdl, MAX_SNAPLEN) != 0) {
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

    scan_ctx.src.sin_addr = thread_ctx->local_sockaddr.sin_addr;
    scan_ctx.src.sin_port = get_random_ephemeral_src_port();
    scan_ctx.src_netmask  = thread_ctx->local_netmask;
    while ((to_scan = scan_queue_dequeue(thread_ctx->scan_queue)) != NULL) {
        scan_ctx.dst.sin_addr = to_scan->resv_host->sockaddr.sin_addr;
        scan_ctx.dst.sin_port = to_scan->port;
        for (t_scan_type scan_type = 0; scan_type < NBR_AVAILABLE_SCANS; scan_type++) {
            if (thread_ctx->scans_to_perform[scan_type]) {
                host_scan_rslt       = NULL;
                scan_ctx.type        = scan_type;
                scan_ctx.port_status = UNDETERMINED;

                if (scan_port(&scan_ctx) != 0) {
                    goto clean_pcap;
                }

                for (size_t i = 0; i < thread_ctx->nbr_hosts; i++) {
                    if (thread_ctx->scan_rslts[i].host = to_scan->resv_host) {
                        host_scan_rslt = &thread_ctx->scan_rslts[i];
                        break;
                    }
                }
                assert(host_scan_rslt != NULL);

                host_scan_rslt->ports[scan_ctx.dst.sin_port][scan_ctx.type] = scan_ctx.port_status;
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