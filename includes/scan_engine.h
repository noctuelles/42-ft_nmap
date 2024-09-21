/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:50:59 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/21 13:17:57 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

#include "parsing.h"

typedef struct s_scan_queue t_scan_queue;

#define NBR_AVAILABLE_SCANS 6 /* Defines the number of available scan types. */
#define MAX_THREAD_COUNT 250  /* Defines the maximum number of threads that can be used. */
#define MAX_RETRIES 3         /* Defines how much try you should perform. */
#define RETRY_DELAY 500       /* Defines the delay between each try in milliseconds. */

typedef bool t_available_scans_list[NBR_AVAILABLE_SCANS];
typedef enum e_scan_type { /* TCP Scan */ STYPE_SYN, STYPE_NULL, STYPE_FIN, STYPE_XMAS, STYPE_ACK, /* UDP Scan */ STYPE_UDP } t_scan_type;

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
    UNDETERMINED = 0,
    OPEN         = 1U,
    CLOSED       = 1U << 1,
    FILTERED     = 1U << 2,
    UNFILTERED   = 1U << 3,
} t_port_status;

typedef struct s_scan_rslt {
    const t_resv_host *resv_host; /* The scanned host. */
    in_port_t          port;      /* The scanned port. */
    t_port_status      status;    /* Status of the port (open,closed,filtered...).*/
    t_scan_type        type;      /* Type of scan (SYN, NULL, ACK...). */
} t_scan_rslt;

typedef struct s_thread_ctx {
    t_available_scans_list scans_to_perform;
    t_scan_rslt           *scan_rslts;   /* Each thread happen an element to this array everytime they finish a port scan. */
    pthread_barrier_t     *sync_barrier; /* This barrier synchronise all threads so that they starts together. */
    t_scan_queue          *scan_queue;   /* Each thread picks a job (an IP:PORT pair) from this queue. */
    struct sockaddr_in     local;        /* The local IP address of the local interface to sniff on. */
    const char            *device;       /* The name of the local interface to sniff on. */
} t_thread_ctx;

void *thread_routine(void *data);

#endif