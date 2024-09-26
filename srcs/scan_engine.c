/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:47:08 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/26 17:05:18 by plouvel          ###   ########.fr       */
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
#include "packet.h"
#include "utils/wrapper.h"

#define FILTER_ICMP_COND                                                                                                                \
    "icmp[0] == 3 and (icmp[1] == 0 or icmp[1] == 2 or icmp[1] == 3 or icmp[1] == 9 or icmp[1] == 10 or icmp[1] == 13) and icmp[8] == " \
    "0x45"
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
process_packet(const u_char *pkt, const struct pcap_pkthdr *pkthdr, t_scan_type scan_type, t_port_status *port_status) {
    struct ip      *iphdr   = NULL;
    struct tcphdr  *tcphdr  = NULL;
    struct icmphdr *icmphdr = NULL;

    /* Used for ICMP */
    struct ip     *orig_iphdr  = NULL;
    struct tcphdr *orig_tcphdr = NULL;
    struct udphdr *orig_udphdr = NULL;

    iphdr = (struct ip *)(pkt + sizeof(struct ethhdr));

    size_t ip_hdrlen = iphdr->ip_hl << 2;

    if (ip_hdrlen < sizeof(struct ip)) {
        return (-1);
    }

    if (iphdr->ip_p == IPPROTO_TCP) {
        tcphdr = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + ip_hdrlen);

        switch (scan_type) {
            case STYPE_SYN:
                if (tcphdr->syn && tcphdr->ack) {
                    *port_status = PORT_OPEN;
                } else if (tcphdr->rst) {
                    *port_status = PORT_CLOSED;
                }
                break;
            case STYPE_NULL:
            case STYPE_FIN:
            case STYPE_XMAS:
                if (tcphdr->rst) {
                    *port_status = PORT_CLOSED;
                }
                break;
            case STYPE_ACK:
                if (tcphdr->rst) {
                    *port_status = PORT_UNFILTERED;
                }
                break;
            default:
                *port_status = PORT_UNDETERMINED;
        }
    } else if (iphdr->ip_p == IPPROTO_ICMP) {
        assert(0 && "Receiving ICMP packet not implemented yet");
        tcphdr = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + ip_hdrlen + sizeof(struct icmphdr));
    } else if (iphdr->ip_p == IPPROTO_UDP) {
        switch (scan_type) {
            case STYPE_UDP:
                *port_status = PORT_OPEN;
                break;
            default:
                *port_status = PORT_UNDETERMINED;
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
    if (pcap_compile(scan_ctx->pcap_hdl, &bpf_prog, filter, 0, scan_ctx->netmask) == PCAP_ERROR) {
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
            send_tcp_packet(scan_ctx->sending_sock, scan_ctx->src.sin_addr.s_addr, scan_ctx->src.sin_port, scan_ctx->dst.sin_addr.s_addr,
                            scan_ctx->dst.sin_port, scan_ctx->type);
        } else if (IS_UDP_SCAN(scan_ctx->type)) {
            assert(0 && "UDP scan not implemented yet");
        }
        try_so_far++;

    arm_poll:
        if ((ret_val = poll(&pollfd, 1, RETRY_DELAY)) == -1) {
            return (-1);
        } else if (ret_val == 0) {
            continue; /* A timeout occured; send the probe again. */
        } else if (ret_val == 1 && pollfd.revents & POLLIN) {
            if ((ret_val = pcap_next_ex(scan_ctx->pcap_hdl, &pkthdr, &pkt)) == 1) {
                if (process_packet(pkt, pkthdr, scan_ctx->type, &scan_ctx->port_status) != 0) {
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
    if ((scan_ctx.pcap_hdl = Pcap_create(thread_ctx->device.name)) == NULL) {
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

    scan_ctx.src.sin_addr = thread_ctx->device.addr;
    scan_ctx.src.sin_port = get_random_ephemeral_src_port();
    scan_ctx.netmask      = thread_ctx->device.netmask;
    while ((to_scan = scan_queue_dequeue(thread_ctx->scan_queue)) != NULL) {
        scan_ctx.dst.sin_addr = to_scan->resv_host->sockaddr.sin_addr;
        scan_ctx.dst.sin_port = to_scan->port;

        if ((ntohl(scan_ctx.dst.sin_addr.s_addr) & LOOPBACK_NETMASK) == LOOPBACK_NETADDR) {
        }

        for (t_scan_type scan_type = 0; scan_type < NBR_AVAILABLE_SCANS; scan_type++) {
            if (thread_ctx->scans_to_perform[scan_type]) {
                host_scan_rslt       = NULL;
                scan_ctx.type        = scan_type;
                scan_ctx.port_status = PORT_UNDETERMINED;

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