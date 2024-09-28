/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hosts.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 11:35:22 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/28 01:49:46 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PARSING_HOSTS_H
#define PARSING_HOSTS_H

#include <netinet/in.h>
#include <stdbool.h>

#include "libft.h"

typedef struct s_resv_host {
    struct sockaddr_in sockaddr; /* Host sockaddr structure. Only ip is filled. */
    struct sockaddr_in if_addr;
    char              *hostname; /* Hostname */
} t_resv_host;

t_list *parse_host_from_str(const char *str);
t_list *parse_host_from_file(const char *filepath);
void    free_resv_host(void *content);

#endif