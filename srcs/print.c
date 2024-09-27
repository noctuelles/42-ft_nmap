/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/27 14:55:45 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/27 14:59:22 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>

#include "ft_nmap.h"
#include "parsing/opts.h"

extern const char *program_invocation_short_name;

void
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

void
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

void
print_results(const t_ft_nmap *ft_nmap) {
    const t_scan_rslt *scan_rslt = NULL;
    char               presentation_ip[INET_ADDRSTRLEN];
    struct servent    *servent = NULL;

    printf("done in about %lu seconds.\n", ft_nmap->scan_end.tv_sec - ft_nmap->scan_start.tv_sec);

    // for (size_t i = 0; i < ft_nmap->nbr_hosts; i++) {
    //     scan_rslt = &ft_nmap->scan_rslts[i];

    //     (void)inet_ntop(AF_INET, &scan_rslt->host->sockaddr.sin_addr, presentation_ip, sizeof(presentation_ip));

    //     printf("Scan result for %s (%s)\n", scan_rslt->host->hostname, presentation_ip);

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