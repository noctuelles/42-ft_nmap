/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/07 14:29:13 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/26 11:23:21 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>

#include "device.h"

#define MIN_PORT 1
#define MAX_PORT_RANGE 1024

#define DFLT_PORT_RANGE_START 1
#define DFLT_PORT_RANGE_END 1024

#define NBR_AVAILABLE_SCANS 6 /* Defines the number of available scan types. */
#define MAX_THREAD_COUNT 250  /* Defines the maximum number of threads that can be used. */
#define MAX_RETRIES 3         /* Defines how much try you should perform. */
#define RETRY_DELAY 500       /* Defines the delay between each try in milliseconds. */
#define MAX_SNAPLEN 100       /* We won't need much data in the packets. */
#define MAX_PORT_RANGE 1024   /* At max, we can scan 1024 ports per host. */
#define NBR_SCANNED_PORTS (g_opts.port_range[1] - g_opts.port_range[0] + 1)

#define DEVICE_DFT 0
#define DEVICE_LOOPBACK 1

typedef bool t_available_scans_list[NBR_AVAILABLE_SCANS];
typedef enum e_scan_type { /* TCP Scan */ STYPE_SYN, STYPE_NULL, STYPE_FIN, STYPE_XMAS, STYPE_ACK, /* UDP Scan */ STYPE_UDP } t_scan_type;

typedef struct s_thread_ctx t_thread_ctx;

typedef struct s_resv_host {
    struct sockaddr_in sockaddr; /* Host sockaddr structure. Only ip is filled. */
    char              *hostname; /* Hostname */
} t_resv_host;

typedef struct s_opts {
    int                    help;
    uint16_t               port_range[2];    /* The port range is inclusive  */
    const char            *host;             /* The host to scan */
    const char            *hosts_file_path;  /* The file containing the hosts to scan. */
    uint16_t               threads;          /* The number of threads to use for the scan */
    t_available_scans_list scans_to_perform; /* Each index */
} t_opts;

typedef struct s_ft_nmap {
    t_device_info   devices_info[2];           /* The devices to use for the scan. */
    t_resv_host    *hosts;                     /* The hosts to scan. */
    bool            hosts_loopback;            /* True if one of the host resolves to the loopback address. */
    size_t          nbr_hosts;                 /* The number of hosts to scan. */
    t_scan_queue   *scan_queue;                /* The scan queue. */
    t_scan_rslt    *scan_rslts;                /* The scan results. The size of this array is nbr_hosts. */
    t_thread_ctx    threads[MAX_THREAD_COUNT]; /* The threads to use for the scan. */
    struct timespec scan_start;                /* The time when the scan started. */
    struct timespec scan_end;                  /* The time when the scan ended. */
} t_ft_nmap;

extern t_opts g_opts;

#endif