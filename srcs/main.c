/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/01 16:56:30 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/13 15:12:13 by plouvel          ###   ########.fr       */
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
#include <unistd.h>

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

typedef struct s_thread_ctx {
    t_scan_queue      *scan_queue;
    struct sockaddr_in local;
    pthread_t          id;
} t_thread_ctx;

static pthread_barrier_t barrier;

void *
thread_routine(void *data) {
    t_thread_ctx            *thread_ctx = data;
    const t_scan_queue_data *elem       = NULL;
    size_t                   nsend      = 0;
    int                      fd         = 0;

    pthread_barrier_wait(&barrier);

    srand(time(NULL));

    if ((fd = Socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        return (NULL);
    }
    while ((elem = scan_queue_dequeue(thread_ctx->scan_queue)) != NULL) {
        struct ip     ip  = {0};
        struct tcphdr tcp = {0};
        uint8_t       packet[IP_MAXPACKET];

        ip.ip_src.s_addr = thread_ctx->local.sin_addr.s_addr;
        ip.ip_dst.s_addr = elem->resv_host->sockaddr.sin_addr.s_addr;
        ip.ip_off        = 0;
        ip.ip_sum        = 0; /* Filled by the kernel when equals to 0. */
        ip.ip_id         = 0; /* Filled when equals to 0 by the kernel. */
        ip.ip_hl         = 5; /* Header length */
        ip.ip_tos        = 0;
        ip.ip_ttl        = 64;
        ip.ip_p          = IPPROTO_TCP;
        ip.ip_v          = IPVERSION;

        const uint16_t ephemeral_port_start = 49152;
        const uint16_t ephemeral_port_end   = 65535;

        tcp.source = htons(rand() % (ephemeral_port_end - ephemeral_port_start + 1) + ephemeral_port_start);
        tcp.dest   = htons(elem->port);
        tcp.window = htons(1024);
        tcp.seq    = htonl(rand());
        tcp.doff   = 5;
        tcp.syn    = 1;

        tcp.check = compute_tcphdr_checksum(ip.ip_src.s_addr, ip.ip_dst.s_addr, tcp, NULL, 0);
        memcpy(packet, &ip, sizeof(ip));
        memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));

        if (Sendto(fd, packet, sizeof(ip) + sizeof(tcp), 0, (const struct sockaddr *)&elem->resv_host->sockaddr,
                   sizeof(struct sockaddr_in)) == -1) {
            return (NULL);
        }

        nsend++;
    }
    printf("Thread [%#lx]: %lu packet sent.\n", thread_ctx->id, nsend);
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

    pcap_if_t         *devs = NULL;
    struct sockaddr_in local_sockaddr, local_netmask;
    char              *local_device_name;

    if (Pcap_findalldevs(&devs) == -1) {
        return (1);
    }
    if (devs == NULL) {
        error(0, 0, "no network interface found");
        return (1);
    }
    for (struct pcap_addr *addr = devs->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            memcpy(&local_sockaddr, addr->addr, sizeof(local_sockaddr));
            memcpy(&local_netmask, addr->netmask, sizeof(local_netmask));
            local_device_name = strdup(devs->name);
            break;
        }
    }
    if (local_device_name == NULL) {
        error(0, 0, "no network interface found");
        return (1);
    }
    pcap_freealldevs(devs);

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
        threads[n].local      = local_sockaddr;
        if (pthread_create(&threads[n].id, NULL, thread_routine, &threads[n]) != 0) {
            return (1);
        }
    }
    for (size_t n = 0; n < g_opts.threads; n++) {
        pthread_join(threads[n].id, NULL);
    }
    return (0);
}