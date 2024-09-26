/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 11:35:22 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/26 11:16:15 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>

#include "libft.h"

t_list *parse_host_from_str(const char *str, bool *loopback);
t_list *parse_host_from_file(const char *filepath, bool *loopback);
void    free_resv_host(void *content);

#endif