/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:47:08 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/29 14:40:31 by plouvel          ###   ########.fr       */
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

#include "net/checksum.h"
#include "net/packet.h"
#include "parsing/opts.h"
#include "pcap/sll.h"
#include "utils/wrapper.h"

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
    bpf_u_int32        netmask;
    struct sockaddr_in src;
    struct sockaddr_in dst;
    t_scan_type        type;
    t_port_status      port_status;
} t_scan_ctx;

static uint8_t
get_tcp_flag(t_scan_type scan_type) {
    switch (scan_type) {
        case STYPE_SYN:
            return (TH_SYN);
        case STYPE_NULL:
            return (0);
        case STYPE_FIN:
            return (TH_FIN);
        case STYPE_XMAS:
            return (TH_FIN | TH_PUSH | TH_URG);
        case STYPE_ACK:
            return (TH_ACK);
        default:
            return (0);
    }
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

    iphdr = (struct ip *)(pkt + sizeof(struct sll_header));

    ip_hdrlen = iphdr->ip_hl << 2;

    if (ip_hdrlen < sizeof(struct ip)) {
        return (-1);
    }

    if (iphdr->ip_p == IPPROTO_TCP) {
        tcphdr = (struct tcphdr *)((u_char *)iphdr + ip_hdrlen);

        switch (scan_ctx->type) {
            case STYPE_SYN:
                if (tcphdr->syn && tcphdr->ack) {
                    scan_ctx->port_status = PORT_OPEN;
                } else if (tcphdr->rst) {
                    scan_ctx->port_status = PORT_CLOSED;
                }
                break;
            case STYPE_NULL:
            case STYPE_FIN:
            case STYPE_XMAS:
                if (tcphdr->rst) {
                    scan_ctx->port_status = PORT_CLOSED;
                }
                break;
            case STYPE_ACK:
                if (tcphdr->rst) {
                    scan_ctx->port_status = PORT_UNFILTERED;
                }
                break;
            default:
                scan_ctx->port_status = PORT_UNDETERMINED;
        }
    } else if (iphdr->ip_p == IPPROTO_ICMP) {
        icmphdr    = (struct icmphdr *)((u_char *)iphdr + ip_hdrlen);
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
                    scan_ctx->port_status = PORT_CLOSED;
                    return (0);
                }
            }

            if (icmphdr->code == ICMP_HOST_UNREACH || icmphdr->code == ICMP_PROT_UNREACH || icmphdr->code == ICMP_PORT_UNREACH ||
                icmphdr->code == ICMP_NET_ANO || icmphdr->code == ICMP_HOST_ANO || icmphdr->code == ICMP_PKT_FILTERED) {
                scan_ctx->port_status = PORT_FILTERED;
            } else {
                return (-1);
            }
        } else {
            return (-1);
        }
    } else if (iphdr->ip_p == IPPROTO_UDP) {
        switch (scan_ctx->type) {
            case STYPE_UDP:
                scan_ctx->port_status = PORT_OPEN;
                break;
            default:
                scan_ctx->port_status = PORT_UNDETERMINED;
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

    (void)snprintf(filter, sizeof(filter), IS_TCP_SCAN(scan_ctx->type) ? FILTER_TCP : FILTER_UDP, presentation_src_ip, presentation_dst_ip,
                   scan_ctx->dst.sin_port, scan_ctx->src.sin_port);
    if (pcap_compile(scan_ctx->pcap_hdl, &bpf_prog, filter, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
        goto ret;
    }
    if (pcap_setfilter(scan_ctx->pcap_hdl, &bpf_prog) != 0) {
        goto clean;
    }
    ret_val = 0;
clean:
    pcap_freecode(&bpf_prog);
ret:
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
    while (try_so_far < g_opts.retrans_nbr) {
        if (try_so_far != 0) {
            scan_ctx->src.sin_port += 1;
        }
        if (apply_pcap_filter(scan_ctx) != 0) {
            return (-1);
        }
        if (IS_TCP_SCAN(scan_ctx->type)) {
            send_tcp_packet(scan_ctx->sending_sock, scan_ctx->src.sin_addr.s_addr, scan_ctx->src.sin_port, scan_ctx->dst.sin_addr.s_addr,
                            scan_ctx->dst.sin_port, get_tcp_flag(scan_ctx->type));
        } else if (IS_UDP_SCAN(scan_ctx->type)) {
            if (send_udp_packet(scan_ctx->sending_sock, scan_ctx->src.sin_addr.s_addr, scan_ctx->src.sin_port,
                                scan_ctx->dst.sin_addr.s_addr, scan_ctx->dst.sin_port) == -1) {
                return (-1);
            }
        }
        try_so_far++;

    arm_poll:
        if ((ret_val = poll(&pollfd, 1, g_opts.retrans_delay)) == -1) {
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

    /* At this point, if the port status is PORT_UNDETERMINED, it means that we didn't receive any response to our probe even after
     * retransmissions. */
    if (scan_ctx->port_status == PORT_UNDETERMINED) {
        switch (scan_ctx->type) {
            case STYPE_SYN:
                scan_ctx->port_status = PORT_FILTERED;
                break;
            case STYPE_NULL:
            case STYPE_FIN:
            case STYPE_XMAS:
                scan_ctx->port_status = PORT_OPEN | PORT_FILTERED;
                break;
            case STYPE_ACK:
                scan_ctx->port_status = PORT_FILTERED;
            case STYPE_UDP:
                scan_ctx->port_status = PORT_OPEN | PORT_FILTERED;
        }
    }

    return (0);
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
    if ((scan_ctx.pcap_hdl = Pcap_create(IFANY)) == NULL) {
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
    if (pcap_datalink(scan_ctx.pcap_hdl) != DLT_LINUX_SLL) {
        goto clean_pcap;
    }

    scan_ctx.src.sin_port = get_random_ephemeral_src_port();
    while ((to_scan = scan_queue_dequeue(thread_ctx->scan_queue)) != NULL) {
        if (g_opts.spoof_ip.s_addr != 0) {
            scan_ctx.src.sin_addr.s_addr = g_opts.spoof_ip.s_addr;
        } else {
            scan_ctx.src.sin_addr.s_addr = to_scan->resv_host->if_addr.sin_addr.s_addr;
        }
        scan_ctx.dst.sin_addr = to_scan->resv_host->sockaddr.sin_addr;
        scan_ctx.dst.sin_port = to_scan->port;

        for (t_scan_type scan_type = 0; scan_type < NBR_AVAILABLE_SCANS; scan_type++) {
            if (g_opts.scans_to_perform[scan_type]) {
                host_scan_rslt       = NULL;
                scan_ctx.type        = scan_type;
                scan_ctx.port_status = PORT_UNDETERMINED;

                if (scan_port(&scan_ctx) != 0) {
                    goto clean_pcap;
                }

                for (size_t i = 0; i < thread_ctx->nbr_hosts; i++) {
                    if (thread_ctx->scan_rslts[i].host == to_scan->resv_host) {
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