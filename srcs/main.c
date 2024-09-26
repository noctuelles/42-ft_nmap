/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/01 16:56:30 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/26 17:38:12 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <error.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ft_nmap.h"
#include "libft.h"
#include "parsing/opts.h"
#include "pcap.h"
#include "queue.h"
#include "scan_engine.h"
#include "utils/wrapper.h"

extern const char *program_invocation_short_name;

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

static void
print_intro(const t_ft_nmap *ft_nmap) {
    time_t    now    = time(NULL);
    struct tm now_tm = *localtime(&now);
    char      date[64];

    (void)strftime(date, sizeof(date), "%c", &now_tm);
    printf("Starting %s on %s.\n", program_invocation_short_name, date);
    printf("Number of hosts to scan : %zu\n", ft_lstsize(ft_nmap->hosts));
    printf("Number of threads : %u\n", g_opts.threads);
    printf("Scanning ports : [%u;%u] - for a total of %u ports. \n", g_opts.port_range[0], g_opts.port_range[1],
           g_opts.port_range[1] - g_opts.port_range[0] + 1);
    printf("Scan(s) to be performed :");
    for (size_t n = 0; n < NBR_AVAILABLE_SCANS; n++) {
        if (g_opts.scans_to_perform[n]) {
            printf(" %s", g_available_scan_types[n]);
        }
    }
    printf("\n");
    printf("Scanning... ");
    fflush(stdout);
}

static void
print_results(const t_ft_nmap *ft_nmap) {
    const t_scan_rslt *scan_rslt = NULL;
    char               presentation_ip[INET_ADDRSTRLEN];
    struct servent    *servent = NULL;

    printf("done in about %lu seconds.\n", ft_nmap->scan_end.tv_sec - ft_nmap->scan_start.tv_sec);

    // for (size_t i = 0; i < nbr_hosts; i++) {
    //     scan_rslt = &scan_rslts[i];

    //     (void)inet_ntop(AF_INET, &scan_rslt->host->sockaddr.sin_addr, presentation_ip, sizeof(presentation_ip));

    //     printf("Scan result for %s (%s)\n", scan_rslt->host->hostname, presentation_ip);
    //     printf("port\t");
    //     for (t_scan_type scan_type = 0; scan_type < NBR_AVAILABLE_SCANS; scan_type++) {
    //         if (g_opts.scans_to_perform[scan_type]) {
    //             switch (scan_type) {
    //                 case STYPE_SYN:
    //                     printf("syn\t");
    //                     break;
    //                 case STYPE_NULL:
    //                     printf("null\t");
    //                     break;
    //                 case STYPE_FIN:
    //                     printf("fin\t");
    //                     break;
    //                 case STYPE_ACK:
    //                     printf("ack\t");
    //                     break;
    //                 case STYPE_XMAS:
    //                     printf("xmas\t");
    //                     break;
    //                 case STYPE_UDP:
    //                     printf("udp\t");
    //                     break;
    //             }
    //         }
    //     }
    //     printf("\n");

    //     for (in_port_t port = g_opts.port_range[0]; port <= g_opts.port_range[1]; port++) {
    //         printf("%u\t", port);
    //         for (t_scan_type scan_type = 0; scan_type < NBR_AVAILABLE_SCANS; scan_type++) {
    //             if (g_opts.scans_to_perform[scan_type]) {
    //                 switch (scan_rslt->ports[port][scan_type]) {
    //                     case PORT_OPEN:
    //                         printf("open\t");
    //                         break;
    //                     case PORT_CLOSED:
    //                         printf("closed\t");
    //                         break;
    //                     case PORT_FILTERED:
    //                         printf("filtered\t");
    //                         break;
    //                     case PORT_UNFILTERED:
    //                         printf("unfiltered\t");
    //                         break;
    //                     case PORT_OPEN | PORT_FILTERED:
    //                         printf("open|filtered\t");
    //                         break;
    //                     default:
    //                         printf("unkown");
    //                         break;
    //                 }
    //             }
    //         }
    //         printf("\n");
    //     }
    // }
}

/**
 * @brief Cleanup the ft_nmap structure and the associated resources.
 *
 * @param ft_nmap The ft_nmap structure to cleanup.
 */
static void
cleanup(t_ft_nmap *ft_nmap) {
    ft_lstclear(&ft_nmap->hosts, free_resv_host);
    free(ft_nmap->scan_rslts);
    free_scan_queue(ft_nmap->scan_queue);
    free(ft_nmap->devices_info[DEVICE_DFT].name);
    free(ft_nmap->devices_info[DEVICE_LOOPBACK].name);
}

/**
 * @brief Get the suitable interface for the scan.
 *
 * @param devices The devices list, this is a result parameter.
 * @param loopback If this parameter is true, the function will also fill the loopback device section of the devices array.
 * @return int -1 on error, 0 on success.
 */
static int
get_devices(t_device_info devices[2], bool loopback) {
    pcap_if_t *devs = NULL;
    int        ret  = -1;

    if (Pcap_findalldevs(&devs) == PCAP_ERROR) {
        return (-1);
    }
    if (devs == NULL) {
        error(0, 0, "no network interface found.");
        return (-1);
    }
    if (get_suitable_interface(devs, &devices[DEVICE_DFT], 0) == -1) {
        error(0, 0, "no suitable network interface found.");
        goto cleanup;
    }
    if (loopback) {
        error(0, 0, "no suitable loopback interface found.");
        if (get_suitable_interface(devs, &devices[DEVICE_LOOPBACK], PCAP_IF_LOOPBACK) == -1) {
            free(devices[DEVICE_DFT].name);
            goto cleanup;
        }
    }
    ret = 0;
cleanup:
    pcap_freealldevs(devs);
    return (ret);
}

int
main(int argc, char **argv) {
    t_ft_nmap ft_nmap    = {0};
    size_t    i          = 0;
    int      *thread_ret = NULL;
    int       ret        = 1;

    if (parse_opts(argc, argv, &g_opts) == -1) {
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
    /* Resolves hosts. */
    if (g_opts.host) {
        if ((ft_nmap.hosts = parse_host_from_str(g_opts.host, &ft_nmap.hosts_loopback)) == NULL) {
            return (1);
        }
    } else if (g_opts.hosts_file_path) {
        if ((ft_nmap.hosts = parse_host_from_file(g_opts.hosts_file_path, &ft_nmap.hosts_loopback)) == NULL) {
            return (1);
        }
    }
    ft_nmap.nbr_hosts = ft_lstsize(ft_nmap.hosts);
    /* Select proper interfaces for scan. */
    if (get_devices(ft_nmap.devices_info, ft_nmap.hosts_loopback) == -1) {
        goto cleanup;
    }
    /* Get scan ressources and fill the task queue. */
    if ((ft_nmap.scan_rslts = Malloc(sizeof(t_scan_rslt) * ft_nmap.nbr_hosts)) == NULL) {
        goto cleanup;
    }
    if ((ft_nmap.scan_queue = new_scan_queue(ft_nmap.nbr_hosts, NBR_SCANNED_PORTS)) == NULL) {
        goto cleanup;
    }
    for (t_list *host = ft_nmap.hosts; host != NULL; host = host->next) {
        ft_nmap.scan_rslts[i].host = host->content;
        for (in_port_t port = g_opts.port_range[0]; port <= g_opts.port_range[1]; port++) {
            scan_queue_enqueue(ft_nmap.scan_queue, host->content, port);
        }
    }
    /* Fill threads context and launch them. */
    print_intro(&ft_nmap);
    (void)clock_gettime(CLOCK_MONOTONIC, &ft_nmap.scan_start);
    for (i = 0; i < g_opts.threads; i++) {
        ft_nmap.threads[i].device      = ft_nmap.devices_info[DEVICE_DFT];
        ft_nmap.threads[i].scan_queue  = ft_nmap.scan_queue;
        ft_nmap.threads[i].scan_rslts  = ft_nmap.scan_rslts;
        ft_nmap.threads[i].nbr_hosts   = ft_nmap.nbr_hosts;
        ft_nmap.threads[i].thread_type = THREAD_HOST_REMOTE;
        memcpy(&ft_nmap.threads[i].scans_to_perform, &g_opts.scans_to_perform, sizeof(g_opts.scans_to_perform));

        if (pthread_create(&ft_nmap.threads[i].thread_id, NULL, thread_routine, &ft_nmap.threads[i]) != 0) {
            error(0, 0, "failed to create a thread.");
            goto cleanup;
        }
    }
    for (i = 0; i < g_opts.threads; i++) {
        if (pthread_join(ft_nmap.threads[i].thread_id, (void **)&thread_ret) != 0) {
            goto cleanup;
        }
        if (*thread_ret != 0) {
            error(0, 0, "a fatal error occured in one of the threads while scanning.");
            goto cleanup;
        }
    }
    (void)clock_gettime(CLOCK_MONOTONIC, &ft_nmap.scan_end);
    print_results(&ft_nmap);
    ret = 0;
cleanup:
    cleanup(&ft_nmap);
    return (ret);
}