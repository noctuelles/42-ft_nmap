/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: etran <etran@student.42.fr>                +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/01 16:56:30 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/20 18:41:41 by etran            ###   ########.fr       */
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
#include "libft.h"
#include "opts_parsing.h"
#include "parsing.h"
#include "pcap.h"
#include "queue.h"
#include "scan_engine.h"
#include "wrapper.h"

#include "type.h"

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


static FT_RESULT
_retrieve_devices(pcap_if_t* devices) {
    if (Pcap_findalldevs(&devices) == 1) {
        return (FT_ERROR);
    }
    if (devices == NULL) {
        error(0, 0, "no network interface found");
        return (FT_ERROR);
    }
    return (FT_SUCCESS);
}

static FT_RESULT
_retrieve_hosts(t_list** hosts) {
    if (g_opts.host != NULL && g_opts.hosts_file_path != NULL) {
        error(0, 0, "cannot set both the host and the file options");
        return (FT_ERROR);
    }
    if (g_opts.host == NULL && g_opts.hosts_file_path == NULL) {
        error(0, 0, "at least provide a host or a file containing the hosts to scan");
        return (FT_ERROR);
    }

    if (g_opts.host) {
        *hosts = parse_host_from_str(g_opts.host);
    } else if (g_opts.hosts_file_path) {
        *hosts = parse_host_from_file(g_opts.hosts_file_path);
    }

    if (hosts == NULL)
        return (FT_ERROR);
    return (FT_SUCCESS);
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

    t_list *hosts = NULL;
    if (_retrieve_hosts(&hosts) == FT_ERROR) {
        return (1);
    }

    pcap_if_t         *devices = NULL;
    if (_retrieve_devices(devices) == FT_ERROR) {
        return (1);
    }

    struct sockaddr_in local_sockaddr, local_netmask;
    char              *local_device_name;

    for (struct pcap_addr *addr = devices->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            memcpy(&local_sockaddr, addr->addr, sizeof(local_sockaddr));
            memcpy(&local_netmask, addr->netmask, sizeof(local_netmask));
            local_device_name = strdup(devices->name);
            break;
        }
    }
    if (local_device_name == NULL) {
        error(0, 0, "no network interface found");
        return (1);
    }
    pcap_freealldevs(devices);

    t_scan_queue *scan_queue = NULL;

    printf("There is %u hosts to scan.\n", ft_lstsize(hosts));
    if ((scan_queue = new_scan_queue(ft_lstsize(hosts), (g_opts.port_range[1] - g_opts.port_range[0]) + 1)) == NULL) {
        return (1);
    }
    for (t_list *elem = hosts; elem != NULL; elem = elem->next) {
        for (uint16_t port = g_opts.port_range[0]; port <= g_opts.port_range[1]; port++) {
            scan_queue_enqueue(scan_queue, elem->content, port, SYN);
        }
    }

    // const t_scan_queue_data *elem = NULL; /* Current scan element */
    // while ((elem = scan_queue_dequeue(scan_queue)) != NULL) {
    //     printf("%p\n", (void *)elem->resv_host);
    // }

    // return (0);

    pthread_t         threads_id[MAX_THREAD_COUNT];
    t_thread_ctx      threads[MAX_THREAD_COUNT];
    int              *thread_ret;
    pthread_barrier_t barrier;
    t_scan_rslt      *scan_rslts;
    size_t            n_probes = ft_lstsize(hosts) * ((g_opts.port_range[1] - g_opts.port_range[0]) + 1);

    if ((scan_rslts = Malloc(n_probes * sizeof(t_scan_rslt))) == NULL) {
        return (1);
    }
    pthread_barrier_init(&barrier, NULL, g_opts.threads);
    for (size_t n = 0; n < g_opts.threads; n++) {
        threads[n].device       = local_device_name;
        threads[n].scan_queue   = scan_queue;
        threads[n].local        = local_sockaddr;
        threads[n].scan_rslts   = scan_rslts;
        threads[n].sync_barrier = &barrier;
        if (pthread_create(&threads_id[n], NULL, thread_routine, &threads[n]) != 0) {
            return (1);
        }
    }
    for (size_t n = 0; n < g_opts.threads; n++) {
        pthread_join(threads_id[n], (void **)&thread_ret);
        if (*thread_ret != 0) {
            puts("An error occured in a thread.");
            return (1);
        }
    }

    // for (size_t n = 0; n < n_probes; n++) {
    //     printf("%s:%u is ", inet_ntoa(scan_rslts[n].resv_host->sockaddr.sin_addr), scan_rslts[n].port);
    //     switch (scan_rslts[n].status) {
    //         case OPEN:
    //             printf("OPEN\n");
    //             break;
    //         case UNDETERMINED:
    //         case CLOSED:
    //             printf("CLOSED\n");
    //             break;
    //         case FILTERED:
    //             printf("FILTERED\n");
    //             break;
    //         default:
    //             printf("NOT HANDLED\n");
    //     }
    // }

    return (0);
}