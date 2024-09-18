/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   logger.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/18 15:23:22 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 15:26:36 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pthread.h>
#include <stdio.h>

static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

void
log_info(const char *msg) {
    pthread_mutex_lock(&g_log_lock);
    printf("%s\n");
    pthread_mutex_unlock(&g_log_lock);
}
