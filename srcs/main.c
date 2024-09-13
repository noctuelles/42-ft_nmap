/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/01 16:56:30 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/13 13:58:59 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <error.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "checksum.h"
#include "libft.h"
#include "opts_parsing.h"
#include "parsing.h"
#include "pcap.h"
#include "queue.h"
#include "wrapper.h"

extern const char *program_invocation_short_name;
t_opts             g_opts = {0}; /* Program options */

static void
print_usage(void) {
    printf("Usage: %s [OPTIONS] - this version only support IPv4.\n", program_invocation_short_name);
    printf("Options:\n");
    printf("  --help\t\tPrint this help message.\n");
    printf("  --ports, -p\t\tThe port range to scan. The port range is inclusive and in the form <port>-<port>.\n");
    printf("  --host\t\tThe host to scan. Either a valid IPv4 address or a hostname.\n");
    printf("  --speedup, -w\t\tThe number of threads to use for the scan. \n");
    printf(
        "  --scan, -s\t\tThe type of scan to perform. The scan type is a comma separated list of the following types: SYN, NULL, FIN, "
        "XMAS, ACK, UDP.\n");
    printf(
        "  --file, -f\t\tThe file containing the hosts to scan. Note that you cannot set the -f and -h options : it's one or another, not "
        "both.\n");
}

/**
 * @brief This handler is called by pcap_loop when a packet is received.
 *
 * @param user User provided struct.
 * @param pkthdr The packet header.
 * @param packet The packet data.
 */
void
packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user;
    (void)pkthdr;

    // struct ethhdr *ethhdr = NULL;
    struct ip     *ip     = NULL;
    struct tcphdr *tcphdr = NULL;

    // ethhdr = (struct ethhdr *)packet;

    /* Do we have to check if the packet is big enough to accomodate everything ? */

    // puts("** RECEIVED PACKET **\n");

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

    // printf("IP version: %u\n", ip->ip_v);
    // printf("IP header length: %lu\n", ip_hdrlen);
    // printf("IP total length: %u\n", ntohs(ip->ip_len));
    // printf("IP protocol: %u\n", ip->ip_p);
    // printf("Source IP address: %s\n", inet_ntoa(ip->ip_src));
    // printf("Destination IP address: %s\n\n", inet_ntoa(ip->ip_dst));

    tcphdr = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_hdrlen);

    printf("Source port: %u\n", ntohs(tcphdr->source));
    // printf("Destination port: %u\n", ntohs(tcphdr->dest));
    // printf("TCP Flags: ");
    // if (tcphdr->syn) {
    //     printf("SYN ");
    // }
    // if (tcphdr->ack) {
    //     printf("ACK ");
    // }
    // if (tcphdr->fin) {
    //     printf("FIN ");
    // }
    // if (tcphdr->rst) {
    //     printf("RST ");
    // }
    // if (tcphdr->psh) {
    //     printf("PSH ");
    // }
    // if (tcphdr->urg) {
    //     printf("URG ");
    // }
    printf("\n");
}

typedef struct s_thread_ctx {
    t_scan_queue             *scan_queue;
    const struct sockaddr_in *local;
    pthread_t                 id;
} t_thread_ctx;

static pthread_mutex_t   print_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;

void *
thread_routine(void *data) {
    t_thread_ctx *ctx   = data;
    size_t        nscan = 0;

    pthread_mutex_lock(&print_lock);
    printf("Thread [%lu]: Started\n", ctx->id);
    pthread_mutex_unlock(&print_lock);

    const t_scan_queue_data *elem = NULL;

    pthread_barrier_wait(&barrier);

    while ((elem = scan_queue_dequeue(ctx->scan_queue)) != NULL) {
        // pthread_mutex_lock(&print_lock);
        // printf("Thread [%#lx]: Scanning %s:%u\n", ctx->id, inet_ntoa(elem->resv_host->sockaddr.sin_addr), elem->port);
        nscan += 1;
        // pthread_mutex_unlock(&print_lock);
    }

    pthread_mutex_lock(&print_lock);
    printf("Thread [%#lx]: Scanned %lu\n", ctx->id, nscan);
    pthread_mutex_unlock(&print_lock);
    return (NULL);
}

#define FILTER "dst host %s and (icmp or ((tcp) and (src host %s)))"

/* https://www.tcpdump.org/pcap.html */
int
main(int argc, char **argv) {
    if (parse_opts(argc, argv, &g_opts) == 1) {
        return (1);
    }
    if (g_opts.help) {
        print_usage();
        return (0);
    }
    if (g_opts.host != NULL && g_opts.hosts_file_path != NULL) {
        error(0, 0, "cannot set both the host and the file options");
        return (1);
    }
    if (g_opts.host == NULL && g_opts.hosts_file_path == NULL) {
        error(0, 0, "at least provide a host or a file containing the hosts to scan");
        return (1);
    }

    t_list *hosts = NULL;

    if (g_opts.host) {
        if ((hosts = parse_host_from_str(g_opts.host)) == NULL) {
            return (1);
        }
    } else if (g_opts.hosts_file_path) {
        if ((hosts = parse_host_from_file(g_opts.hosts_file_path)) == NULL) {
            return (1);
        }
    }

    t_scan_queue *scan_queue = NULL;
    if ((scan_queue = new_scan_queue(ft_lstsize(hosts), (g_opts.port_range[1] - g_opts.port_range[0]) + 1)) == NULL) {
        return (1);
    }
    for (t_list *elem = hosts; elem != NULL; elem = elem->next) {
        for (uint16_t port = g_opts.port_range[0]; port <= g_opts.port_range[1]; port++) {
            scan_queue_enqueue(scan_queue, elem->content, port);
        }
    }

    t_thread_ctx threads[MAX_THREAD_COUNT];

    if (pthread_barrier_init(&barrier, NULL, g_opts.threads) != 0) {
        return (1);
    }
    for (size_t n = 0; n < g_opts.threads; n++) {
        threads[n].scan_queue = scan_queue;
        if (pthread_create(&threads[n].id, NULL, thread_routine, &threads[n]) != 0) {
            return (1);
        }
    }
    for (size_t n = 0; n < g_opts.threads; n++) {
        pthread_join(threads[n].id, NULL);
    }

    // pcap_if_t *devs = NULL;

    // t_resv_host       *dest = hosts->content;
    // struct sockaddr_in local_sockaddr, local_netmask;
    // char              *local_device_name;

    // if (Pcap_findalldevs(&devs) == -1) {
    //     return (1);
    // }
    // if (devs == NULL) {
    //     error(0, 0, "no network interface found");
    //     return (1);
    // }
    // for (struct pcap_addr *addr = devs->addresses; addr != NULL; addr = addr->next) {
    //     if (addr->addr->sa_family == AF_INET) {
    //         memcpy(&local_sockaddr, addr->addr, sizeof(local_sockaddr));
    //         memcpy(&local_netmask, addr->netmask, sizeof(local_netmask));
    //         local_device_name = strdup(devs->name);
    //         break;
    //     }
    // }
    // if (local_device_name == NULL) {
    //     error(0, 0, "no network interface found");
    //     return (1);
    // }
    // pcap_freealldevs(devs);

    // pcap_t            *handle = NULL;
    // char               filter[256];
    // struct bpf_program filter_program;

    // char srchost[INET_ADDRSTRLEN];
    // char dsthost[INET_ADDRSTRLEN];

    // inet_ntop(AF_INET, &local_sockaddr.sin_addr, srchost, INET_ADDRSTRLEN);
    // inet_ntop(AF_INET, &dest->sockaddr.sin_addr, dsthost, INET_ADDRSTRLEN);

    // snprintf(filter, sizeof(filter), FILTER, srchost, dsthost);

    // if ((handle = Pcap_open_live(local_device_name, BUFSIZ, 1, 1000)) == NULL) {
    //     return (1);
    // }
    // if (Pcap_compile(handle, &filter_program, filter, 0, local_netmask.sin_addr.s_addr) == -1) {
    //     return (1);
    // }
    // if (Pcap_setfilter(handle, &filter_program) == -1) {
    //     return (1);
    // }

    // printf("Using interface device %s\n", local_device_name);
    // printf("Local IP address: %s\n", inet_ntoa(local_sockaddr.sin_addr));
    // printf("Destination IP address: %s\n", inet_ntoa(dest->sockaddr.sin_addr));
    // printf("Filter: %s\n\n", filter);

    // int sockfd = 0;

    // if ((sockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
    //     return (1);
    // }
    // srand(time(NULL));

    // uint16_t port = g_opts.port_range[0];

    // struct ip     ip  = {0};
    // struct tcphdr tcp = {0};
    // uint8_t       packet[IP_MAXPACKET];

    // ip.ip_src.s_addr = local_sockaddr.sin_addr.s_addr;
    // ip.ip_dst.s_addr = dest->sockaddr.sin_addr.s_addr;
    // ip.ip_off        = 0;
    // ip.ip_sum        = 0; /* Filled by the kernel when equals to 0. */
    // ip.ip_id         = 0; /* Filled when equals to 0 by the kernel. */
    // ip.ip_hl         = 5; /* Header length */
    // ip.ip_tos        = 0;
    // ip.ip_ttl        = 64;
    // ip.ip_p          = IPPROTO_TCP;
    // ip.ip_v          = IPVERSION;

    // const uint16_t ephemeral_port_start = 49152;
    // const uint16_t ephemeral_port_end   = 65535;

    // while (port <= g_opts.port_range[1]) {
    //     tcp.source = htons(rand() % (ephemeral_port_end - ephemeral_port_start + 1) + ephemeral_port_start);
    //     tcp.dest   = htons(port);
    //     tcp.window = htons(1024);
    //     tcp.seq    = htonl(rand());
    //     tcp.doff   = 5;
    //     tcp.syn    = 1;

    //     tcp.check = compute_tcphdr_checksum(ip.ip_src.s_addr, ip.ip_dst.s_addr, tcp, NULL, 0);
    //     memcpy(packet, &ip, sizeof(ip));
    //     memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

    //     if (Sendto(sockfd, packet, sizeof(ip) + sizeof(tcp), 0, (struct sockaddr *)&dest->sockaddr, sizeof(dest->sockaddr)) == -1) {
    //         return (1);
    //     }

    //     port++;
    // }

    // if (pcap_loop(handle, 0, packet_handler, NULL) == -1) {
    //     return (1);
    // }

    return (0);
}