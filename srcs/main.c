/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/01 16:56:30 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 11:00:22 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <assert.h>
#include <error.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "checksum.h"
#include "hash.h"
#include "libft.h"
#include "opts_parsing.h"
#include "parsing.h"
#include "pcap.h"
#include "queue.h"
#include "scan_engine.h"
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

#define FILTER "dst host %s and (icmp or ((tcp) and (src host %s)))"

void
get_entropy(char key[16]) {
    FILE *fp = NULL;

    srand(time(NULL));
    if ((fp = fopen("/dev/urandom", "r")) != NULL) {
        (void)fread((void *)key, 16, 1, fp);
    } else {
        *((int *)&key[0])  = rand();
        *((int *)&key[4])  = rand();
        *((int *)&key[8])  = rand();
        *((int *)&key[12]) = rand();
    }
    fclose(fp);
}

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

    char key[16];
    get_entropy(key);

    t_scan_queue *scan_queue = NULL;
    size_t        n_probes   = ft_lstsize(hosts) * (g_opts.port_range[1] - g_opts.port_range[0]) + 1;

    if ((scan_queue = new_scan_queue(ft_lstsize(hosts), (g_opts.port_range[1] - g_opts.port_range[0]) + 1)) == NULL) {
        return (1);
    }
    for (t_list *elem = hosts; elem != NULL; elem = elem->next) {
        for (uint16_t port = g_opts.port_range[0]; port <= g_opts.port_range[1]; port++) {
            scan_queue_enqueue(scan_queue, elem->content, port, SYN_SCAN);
        }
    }

    t_thread_ctx      send_threads[2];
    t_recv_thread_ctx recv_thread;
    char              filter[512];
    char              ip_dst[INET_ADDRSTRLEN];
    char              ip_src[INET_ADDRSTRLEN];
    t_resv_host      *host = hosts->content;
    pthread_barrier_t barrier;  // this barrier is used to synchronise the sender and recv threads.

    strcpy(ip_dst, inet_ntoa(host->sockaddr.sin_addr));
    strcpy(ip_src, inet_ntoa(local_sockaddr.sin_addr));

    snprintf(filter, sizeof(filter), FILTER, ip_src, ip_dst);

    printf("Filter is : %s\n", filter);

    if (pthread_barrier_init(&barrier, NULL, 3) != 0) {
        return (1);
    }

    for (size_t n = 0; n < 2; n++) {
        send_threads[n].scan_queue = scan_queue;
        send_threads[n].local      = local_sockaddr;
        send_threads[n].key        = key;
        send_threads[n].barrier    = &barrier;
        if (pthread_create(&send_threads[n].id, NULL, sender_thread, &send_threads[n]) != 0) {
            return (1);
        }
        pthread_detach(send_threads[n].id);
    }

    recv_thread.device    = local_device_name;
    recv_thread.filter    = filter;
    recv_thread.n_probes  = n_probes;
    recv_thread.scan_type = SYN_SCAN;
    recv_thread.barrier   = &barrier;
    recv_thread.key       = key;
    if (pthread_create(&recv_thread.id, NULL, receiver_thread, &recv_thread) != 0) {
        return (1);
    }
    pthread_join(recv_thread.id, NULL);
    return (0);
}