/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hosts.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 11:35:22 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/26 15:21:55 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PARSING_HOSTS_H
#define PARSING_HOSTS_H

#include <netinet/in.h>
#include <stdbool.h>

#include "libft.h"

typedef struct s_resv_host {
    struct sockaddr_in sockaddr; /* Host sockaddr structure. Only ip is filled. */
    char              *hostname; /* Hostname */
} t_resv_host;

t_list *parse_host_from_str(const char *str, bool *loopback);
t_list *parse_host_from_file(const char *filepath, bool *loopback);
void    free_resv_host(void *content);

#endif