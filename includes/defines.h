/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   defines.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/26 15:32:50 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/28 21:18:01 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef DEFINES_H
#define DEFINES_H

#define NBR_AVAILABLE_SCANS 6  /* Defines the number of available scan types. */
#define MAX_PORT_RANGE 1024    /* At max, we can scan 1024 ports per host. */
#define MIN_PORT 1             /* Defines the minimum port number that can be scanned. */
#define MAX_PORT_RANGE 1024    /* Defines the maximum number of ports that can be scanned. */
#define MAX_RETRANS_NBR 10     /* Defines the maximum number of retransmissions. */
#define MIN_RETRANS_NBR 1      /* Defines the minimum number of retransmissions. */
#define MAX_RETRANS_DELAY 2000 /* Defines the maximum delay between each retransmission in milliseconds. */
#define MIN_RETRANS_DELAY 100  /* Defines the minimum delay between each retransmission in milliseconds. */
#define DFLT_PORT_RANGE_START 1
#define DFLT_PORT_RANGE_END 1024
#define DFLT_RETRANS_NBR 3                 /* Defines how much try you should perform. */
#define DFLT_RETRANS_DELAY 800             /* Defines the delay between each try in milliseconds. */
#define MAX_THREAD_COUNT 250               /* Defines the maximum number of threads that can be used. */
#define MIN_THREAD_COUNT 1                 /* Defines the minimum number of threads that can be used. */
#define DFLT_THREAD_COUNT MIN_THREAD_COUNT /* Defines the default number of threads to use. */
#define MAX_SNAPLEN 100                    /* We won't need much data in the packets. */
#define NBR_SCANNED_PORTS (g_opts.port_range[1] - g_opts.port_range[0] + 1)

#define IFANY "any"

#define IS_TCP_SCAN(scan_type) ((scan_type) >= STYPE_SYN && (scan_type) <= STYPE_ACK)
#define IS_UDP_SCAN(scan_type) ((scan_type) == STYPE_UDP)

#endif