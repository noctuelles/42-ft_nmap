/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/07 14:29:13 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/25 14:29:22 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>

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

typedef bool t_available_scans_list[NBR_AVAILABLE_SCANS];
typedef enum e_scan_type { /* TCP Scan */ STYPE_SYN, STYPE_NULL, STYPE_FIN, STYPE_XMAS, STYPE_ACK, /* UDP Scan */ STYPE_UDP } t_scan_type;

typedef struct s_resv_host {
    struct sockaddr_in sockaddr; /* Host sockaddr structure. Only ip is filled. */
    struct timespec    rtt;      /* Round Trip Time */
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

extern t_opts g_opts;

#endif