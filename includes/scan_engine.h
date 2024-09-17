/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:50:59 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/17 18:47:57 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

typedef struct s_scan_queue t_scan_queue;

typedef enum s_scan_type { /* TCP Scan */ SYN_SCAN, NULL_SCAN, FIN_SCAN, XMAS_SCAN, ACK_SCAN, /* UDP Scan */ UDP_SCAN } t_scan_type;

typedef struct s_send_thread_ctx {
    t_scan_queue      *scan_queue;
    const char        *key;
    struct sockaddr_in local;
    pthread_t          id;
    pthread_barrier_t *barrier;
} t_send_thread_ctx;

typedef struct s_recv_thread_ctx {
    const char        *filter;
    const char        *device;
    const char        *key;
    t_scan_type        scan_type;
    size_t             n_probes;
    pthread_t          id;
    pthread_barrier_t *barrier;
} t_recv_thread_ctx;

void *receiver_thread(void *data);
void *sender_thread(void *data);

#endif