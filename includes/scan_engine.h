/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:50:59 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 11:01:19 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

typedef struct s_scan_queue t_scan_queue;

typedef enum s_scan_type { /* TCP Scan */ SYN_SCAN, NULL_SCAN, FIN_SCAN, XMAS_SCAN, ACK_SCAN, /* UDP Scan */ UDP_SCAN } t_scan_type;

typedef struct s_thread_ctx {
    struct sockaddr_in local;
    t_scan_queue      *scan_queue;
    const char        *device;
    bool               scan_type[6];
    pthread_t          id;
} t_thread_ctx;

void *receiver_thread(void *data);
void *sender_thread(void *data);

#endif