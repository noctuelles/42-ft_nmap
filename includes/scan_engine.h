/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:50:59 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 16:22:46 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

typedef struct s_scan_queue t_scan_queue;

typedef enum e_scan_type { /* TCP Scan */ SYN, NUL, FIN, XMAS, ACK, /* UDP Scan */ UDP } t_scan_type;

typedef enum e_scan_status {
    UNDETERMINED = 0,
    OPEN         = 1U,
    CLOSED       = 1U << 1,
    FILTERED     = 1U << 2,
    UNFILTERED   = 1U << 3,
} t_scan_status;

typedef struct s_scan_rslt {
    t_scan_status      status;
    t_scan_type        type;
    const t_resv_host *resv_host;
    in_port_t          port;
} t_scan_rslt;

typedef struct s_thread_ctx {
    pthread_barrier_t *sync_barrier;
    t_scan_rslt       *scan_rslts;
    struct sockaddr_in local;
    t_scan_queue      *scan_queue;
    const char        *device;
    bool               scan_type[6];
} t_thread_ctx;

void *thread_routine(void *data);

#endif