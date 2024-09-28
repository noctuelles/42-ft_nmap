/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/07 14:29:13 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/28 01:49:01 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>

#include "defines.h"
#include "net/device.h"
#include "parsing/hosts.h"
#include "scan_engine.h"

typedef struct s_ft_nmap {
    t_list         *hosts;                     /* The hosts to scan. */
    size_t          nbr_hosts;                 /* The number of hosts to scan. */
    t_scan_queue   *scan_queue;                /* The scan queue. */
    t_scan_rslt    *scan_rslts;                /* The scan results. The size of this array is nbr_hosts. */
    t_thread_ctx    threads[MAX_THREAD_COUNT]; /* The threads to use for the scan. */
    struct timespec scan_start;                /* The time when the scan started. */
    struct timespec scan_end;                  /* The time when the scan ended. */
} t_ft_nmap;

#endif