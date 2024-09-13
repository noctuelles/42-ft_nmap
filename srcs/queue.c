/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   queue.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/13 11:29:26 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/13 12:02:26 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>

#include "parsing.h"
#include "wrapper.h"

typedef struct s_scan_queue_data {
    const t_resv_host *resv_host;
    uint16_t           port;
} t_scan_queue_data;

typedef struct s_scan_queue {
    t_scan_queue_data *data;

    pthread_mutex_t lock;

    size_t capacity;
    size_t size;
    size_t head;
    size_t tail;
} t_scan_queue;

t_scan_queue *
new_scan_queue(size_t nbr_host, size_t nbr_ports) {
    t_scan_queue *queue = NULL;

    if ((queue = Malloc(sizeof(t_scan_queue))) == NULL) {
        goto err;
    }
    queue->data = NULL;
    if ((queue->data = Malloc(sizeof(t_scan_queue_data) * (nbr_host * nbr_ports))) == NULL) {
        goto err;
    }
    if (pthread_mutex_init(&queue->lock, NULL) != 0) {
        goto err;
    }

    queue->capacity = nbr_host * nbr_ports;
    queue->size     = 0;
    queue->head     = 0;
    queue->tail     = queue->capacity - 1;

    return (queue);
err:
    free(queue->data);
    free(queue);
    return (NULL);
}

void
free_scan_queue(t_scan_queue *queue) {
    pthread_mutex_destroy(&queue->lock);
    free(queue->data);
    free(queue);
}

void
scan_queue_enqueue(t_scan_queue *queue, const t_resv_host *resv_host, uint16_t port) {
    pthread_mutex_lock(&queue->lock);

    if (queue->size == queue->capacity) {
        pthread_mutex_unlock(&queue->lock);
        return;
    }

    queue->tail                        = (queue->tail + 1) % queue->capacity;
    queue->data[queue->tail].resv_host = resv_host;
    queue->data[queue->tail].port      = port;
    queue->size++;

    pthread_mutex_unlock(&queue->lock);
}

const t_scan_queue_data *
scan_queue_dequeue(t_scan_queue *queue) {
    const t_scan_queue_data *data = NULL;

    pthread_mutex_lock(&queue->lock);

    if (queue->size == 0) {
        pthread_mutex_unlock(&queue->lock);
        return (NULL);
    }

    data        = &queue->data[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->size -= 1;

    pthread_mutex_unlock(&queue->lock);

    return (data);
}