/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   defines.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/26 15:32:50 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/27 23:17:36 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef DEFINES_H
#define DEFINES_H

#define NBR_AVAILABLE_SCANS 6 /* Defines the number of available scan types. */
#define MAX_PORT_RANGE 1024   /* At max, we can scan 1024 ports per host. */

#define MIN_PORT 1
#define MAX_PORT_RANGE 1024

#define DFLT_PORT_RANGE_START 1
#define DFLT_PORT_RANGE_END 1024

#define MAX_THREAD_COUNT 250 /* Defines the maximum number of threads that can be used. */
#define MAX_RETRIES 3        /* Defines how much try you should perform. */
#define RETRY_DELAY 500      /* Defines the delay between each try in milliseconds. */
#define MAX_SNAPLEN 100      /* We won't need much data in the packets. */
#define NBR_SCANNED_PORTS (g_opts.port_range[1] - g_opts.port_range[0] + 1)

#define DEVICE_DFT 0
#define DEVICE_LOOPBACK 1

#define LOOPBACK_NETADDR 0x7F000000
#define LOOPBACK_NETMASK 0xFF000000

#define IFANY "any"

#define IS_TCP_SCAN(scan_type) ((scan_type) >= STYPE_SYN && (scan_type) <= STYPE_ACK)
#define IS_UDP_SCAN(scan_type) ((scan_type) == STYPE_UDP)

#endif