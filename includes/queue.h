/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   queue.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/13 11:57:03 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 18:21:28 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef QUEUE_H
#define QUEUE_H

#include "parsing.h"
#include "scan_engine.h"

typedef struct s_scan_queue_data {
    const t_resv_host *resv_host;
    t_scan_type        scan_type;
    uint16_t           port;
} t_scan_queue_data;

typedef struct s_scan_queue t_scan_queue;

t_scan_queue            *new_scan_queue(size_t nbr_host, size_t nbr_ports);
void                     free_scan_queue(t_scan_queue *queue);
size_t                   scan_queue_size(t_scan_queue *queue);
void                     scan_queue_enqueue(t_scan_queue *queue, const t_resv_host *resv_host, uint16_t port, t_scan_type scan_type);
const t_scan_queue_data *scan_queue_dequeue(t_scan_queue *queue);

#endif