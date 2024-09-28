/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/01 16:56:30 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/28 02:15:36 by plouvel          ###   ########.fr       */
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
#include "print.h"
#include "queue.h"
#include "scan_engine.h"
#include "utils/wrapper.h"

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
}

static int
fill_host_if_addr(t_list *hosts) {
    pcap_if_t         *devs      = NULL;
    pcap_if_t         *orig_devs = NULL;
    t_resv_host       *resv_host = NULL;
    int                ret       = -1;
    struct sockaddr_in if_default_addr;
    char               errbuff[PCAP_ERRBUF_SIZE];
    bpf_u_int32        netmask;
    bpf_u_int32        netaddr;

    if (Pcap_findalldevs(&devs) == PCAP_ERROR) {
        return (-1);
    }
    if (devs == NULL) {
        error(0, 0, "no network interface found.");
        return (-1);
    }
    for (struct pcap_addr *addr = devs->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            if_default_addr = *((const struct sockaddr_in *)addr->addr);
        }
    }
    orig_devs = devs;
    devs      = devs->next;
    for (t_list *host = hosts; host != NULL; host = host->next) {
        resv_host = host->content;
        for (pcap_if_t *dev = devs; dev != NULL; dev = dev->next) {
            if (!(dev->flags & PCAP_IF_UP) || !(dev->flags & PCAP_IF_RUNNING) ||
                (dev->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_DISCONNECTED) {
                continue;
            }
            if (pcap_lookupnet(dev->name, &netaddr, &netmask, errbuff) == PCAP_ERROR) {
                continue;
            }
            if (netmask != 0x0 && netaddr != 0x0 && (resv_host->sockaddr.sin_addr.s_addr & netmask) == (netaddr & netmask)) {
                for (struct pcap_addr *addr = dev->addresses; addr != NULL; addr = addr->next) {
                    if (addr->addr->sa_family == AF_INET) {
                        resv_host->if_addr = *((const struct sockaddr_in *)addr->addr);
                        break;
                    }
                }
            }
        }
        /* Assign default interface IP address. */
        if (resv_host->if_addr.sin_addr.s_addr == 0x0) {
            resv_host->if_addr = if_default_addr;
        }
    }
    pcap_freealldevs(orig_devs);
    return (0);
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
        if ((ft_nmap.hosts = parse_host_from_str(g_opts.host)) == NULL) {
            return (1);
        }
    } else if (g_opts.hosts_file_path) {
        if ((ft_nmap.hosts = parse_host_from_file(g_opts.hosts_file_path)) == NULL) {
            return (1);
        }
    }
    ft_nmap.nbr_hosts = ft_lstsize(ft_nmap.hosts);
    /* Select proper interfaces for scan. */
    if (fill_host_if_addr(ft_nmap.hosts) == -1) {
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
        ft_nmap.scan_rslts[i++].host = host->content;
        for (in_port_t port = g_opts.port_range[0]; port <= g_opts.port_range[1]; port++) {
            scan_queue_enqueue(ft_nmap.scan_queue, host->content, port);
        }
    }
    /* Fill threads context and launch them. */
    print_intro(&ft_nmap);
    (void)clock_gettime(CLOCK_MONOTONIC, &ft_nmap.scan_start);
    for (i = 0; i < g_opts.threads; i++) {
        ft_nmap.threads[i].scan_queue  = ft_nmap.scan_queue;
        ft_nmap.threads[i].scan_rslts  = ft_nmap.scan_rslts;
        ft_nmap.threads[i].nbr_hosts   = ft_nmap.nbr_hosts;
        ft_nmap.threads[i].thread_type = THREAD_HOST_REMOTE;

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