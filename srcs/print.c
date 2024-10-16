/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/27 14:55:45 by plouvel           #+#    #+#             */
/*   Updated: 2024/10/16 17:27:34 by plouvel          ###   ########.fr       */
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
    printf("  --help\t\tprint this help message.\n");
    printf("  --ports, -p\t\tThe port range to scan. The port range is inclusive and in the form <port>-<port>.\n");
    printf("  --host\t\tthe host to scan. Either a valid IPv4 address or a hostname.\n");
    printf("  --speedup, -w\t\tthe number of threads to use for the scan (default %u).\n", DFLT_THREAD_COUNT);
    printf("  --retries, -r\t\tthe number of probe retransmissions before giving up (default %u).\n", DFLT_RETRANS_NBR);
    printf("  --delay, -d\t\tthe amount of time in milliseconds before attempting a retransmission (default %u).\n", DFLT_RETRANS_DELAY);
    printf("  --badsum, -b\t\tuse an invalid TCP, UDP checksum for packets sent to target hosts.\n");
    printf("  --spoofip, -S\t\tIP address of the interface you wish to send packets through.\n");
    printf(
        "  --scan, -s\t\tthe type of scan to perform. The scan type is a comma separated list of the following types: SYN, NULL, FIN, "
        "XMAS, ACK, UDP.\n");
    printf(
        "  --file, -f\t\tthe file containing the hosts to scan. Note that you cannot set the -f and -h options : it's one or another, not "
        "both.\n");
}

void
print_intro(const t_ft_nmap *ft_nmap) {
    time_t    now    = time(NULL);
    struct tm now_tm = *localtime(&now);
    char      ip[INET_ADDRSTRLEN];
    char      date[64];

    (void)strftime(date, sizeof(date), "%c", &now_tm);
    printf("Starting %s on %s.\n", program_invocation_short_name, date);
    printf("Number of retransmissions : %u\n", g_opts.retrans_nbr);
    printf("Delay between retransmissions : %ums\n", g_opts.retrans_delay);
    printf("Number of hosts to scan : %u\n", ft_lstsize(ft_nmap->hosts));
    printf("Number of threads : %u\n", g_opts.threads);
    printf("Scanning ports : [%u;%u] - for a total of %u ports. \n", g_opts.port_range[0], g_opts.port_range[1],
           g_opts.port_range[1] - g_opts.port_range[0] + 1);
    if (g_opts.spoof_ip.s_addr != 0) {
        (void)inet_ntop(AF_INET, &g_opts.spoof_ip, ip, sizeof(ip));
        printf("Spoofing with IP : %s\n", ip);
    }
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

// static void
// print_results(const t_ft_nmap *ft_nmap, const char *proto) {}

const char *
get_port_status_str(t_port_status port_status) {
    if (port_status == PORT_UNDETERMINED) {
        return ("undetermined");
    }
    if (port_status == PORT_OPEN) {
        return ("open");
    }
    if (port_status == PORT_CLOSED) {
        return ("closed");
    }
    if (port_status == PORT_FILTERED) {
        return ("filtered");
    }
    if (port_status == PORT_UNFILTERED) {
        return ("unfiltered");
    }
    if (port_status == (PORT_OPEN | PORT_FILTERED)) {
        return ("open|filtered");
    }
    return ("unknown");
}

void
print_results(const t_ft_nmap *ft_nmap) {
    const t_scan_rslt *scan_rslt = NULL;
    char               presentation_ip[INET_ADDRSTRLEN];
    struct servent    *servent = NULL;
    char               buffer[256];
    size_t             n_print = 0;

    printf("done in about %lu seconds.\n\n", ft_nmap->scan_end.tv_sec - ft_nmap->scan_start.tv_sec);

    for (size_t i = 0; i < ft_nmap->nbr_hosts; i++) {
        n_print   = 0;
        scan_rslt = &ft_nmap->scan_rslts[i];

        (void)inet_ntop(AF_INET, &scan_rslt->host->sockaddr.sin_addr, presentation_ip, sizeof(presentation_ip));
        printf("Scan result for %s (%s)\n\n", scan_rslt->host->hostname, presentation_ip);

        snprintf(buffer, sizeof(buffer), "Port");
        n_print += printf("%-8s", buffer);
        for (t_scan_type scan_type = 0; scan_type < NBR_AVAILABLE_SCANS; scan_type++) {
            if (g_opts.scans_to_perform[scan_type]) {
                snprintf(buffer, sizeof(buffer), "%s Scan", g_available_scan_types[scan_type]);
                n_print += printf("%-20s", buffer);
            }
        }
        n_print += printf("Service Name (if applicable)");
        printf("\n");
        for (size_t n = 0; n < n_print; n++) {
            printf("-");
        }
        printf("\n");

        for (in_port_t port = g_opts.port_range[0]; port <= g_opts.port_range[1]; port++) {
            printf("%-8u", port);
            for (t_scan_type scan_type = 0; scan_type < NBR_AVAILABLE_SCANS; scan_type++) {
                if (g_opts.scans_to_perform[scan_type]) {
                    printf("%-20s", get_port_status_str(scan_rslt->ports[port][scan_type]));
                }
            }
            if ((servent = getservbyport(htons(port), "tcp")) != NULL) {
                snprintf(buffer, sizeof(buffer), "%s(tcp) ", servent->s_name);
            } else {
                snprintf(buffer, sizeof(buffer), "unknown(tcp) ");
            }
            printf("%-13s", buffer);

            if ((servent = getservbyport(htons(port), "udp")) != NULL) {
                snprintf(buffer, sizeof(buffer), "%s(udp) ", servent->s_name);
            } else {
                snprintf(buffer, sizeof(buffer), "unknown(udp) ");
            }
            printf("%s", buffer);

            printf("\n");
        }
        if (i + 1 < ft_nmap->nbr_hosts) {
            printf("\n");
        }
    }
}