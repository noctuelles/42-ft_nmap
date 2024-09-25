/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 11:35:22 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/25 14:26:53 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PARSING_H
#define PARSING_H

#include <netinet/in.h>

#include "libft.h"

t_list *parse_host_from_str(const char *str);
t_list *parse_host_from_file(const char *filepath);
void    free_resv_host(void *content);

#endif