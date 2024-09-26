/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:50:59 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/26 11:26:21 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

#include "ft_nmap.h"

typedef struct s_scan_queue t_scan_queue;

#define LOOPBACK_NETADDR 0x7F000000
#define LOOPBACK_NETMASK 0xFF000000

#define IS_TCP_SCAN(scan_type) ((scan_type) >= STYPE_SYN && (scan_type) <= STYPE_ACK)
#define IS_UDP_SCAN(scan_type) ((scan_type) == STYPE_UDP)

extern const char *g_available_scan_types[NBR_AVAILABLE_SCANS];

/*
    The port status differs from each scan type. The program interpret a port status in function of the probe response. This is a summary
    for each different scan type :

        TCP SYN :

            +-------------------------------------------------------------+----------------+
            |                       Probe Response                        | Assigned State |
            +-------------------------------------------------------------+----------------+
            | TCP SYN/ACK response                                        | open           |
            | TCP RST response                                            | closed         |
            | No response received (even after retransmissions)           | filtered       |
            | ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) | filtered       |
            +-------------------------------------------------------------+----------------+

        TCP NULL, FIN, XMAS :

            +-------------------------------------------------------------+----------------+
            |                       Probe Response                        | Assigned State |
            +-------------------------------------------------------------+----------------+
            | No response received (even after retransmissions)           | open|filtered  |
            | TCP RST packet                                              | closed         |
            | ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) | filtered       |
            +-------------------------------------------------------------+----------------+

        TCP ACK :

            +-------------------------------------------------------------+----------------+
            |                       Probe Response                        | Assigned State |
            +-------------------------------------------------------------+----------------+
            | TCP RST response                                            | unfiltered     |
            | No response received (even after retransmissions)           | filtered       |
            | ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) | filtered       |
            +-------------------------------------------------------------+----------------+

        UDP :

            +-----------------------------------------------------------------+----------------+
            |                         Probe Response                          | Assigned State |
            +-----------------------------------------------------------------+----------------+
            | Any UDP response from target port (unusual)                     | open           |
            | No response received (even after retransmissions)               | open|filtered  |
            | ICMP port unreachable error (type 3, code 3)                    | closed         |
            | Other ICMP unreachable errors (type 3, code 1, 2, 9, 10, or 13) | filtered       |
            +-----------------------------------------------------------------+----------------+
*/

typedef enum e_port_status {
    PORT_UNDETERMINED = 0,
    PORT_OPEN         = 1U,
    PORT_CLOSED       = 1U << 1,
    PORT_FILTERED     = 1U << 2,
    PORT_UNFILTERED   = 1U << 3,
} t_port_status;

typedef enum e_thread_type {
    HOST_LOCALHOST_THREAD,
    HOST_REMOTE_THREAD,
} t_thread_type;

typedef struct s_scan_rslt {
    const t_resv_host *host; /* The scanned host. */
    t_port_status      ports[MAX_PORT_RANGE][NBR_AVAILABLE_SCANS];
} t_scan_rslt;

typedef struct s_thread_ctx {
    t_available_scans_list scans_to_perform;
    t_device_info          devices[2];
    t_scan_rslt           *scan_rslts;
    size_t                 nbr_hosts;
    t_scan_queue          *scan_queue; /* Each thread picks a job (an IP:PORT pair) from this queue. */
    pthread_t              thread_id;
} t_thread_ctx;

extern const char *g_available_scan_types[NBR_AVAILABLE_SCANS];

void *thread_routine(void *data);

#endif