/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 11:35:22 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/10 13:19:25 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>

#include "libft.h"

typedef struct s_resv_host {
    struct sockaddr_in sockaddr;
    char              *hostname;
} t_resv_host;

t_list *parse_host_from_str(const char *str);
t_list *parse_host_from_file(const char *filepath);
void    free_resv_host(void *content);

#endif