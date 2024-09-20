/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/07 14:29:13 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/20 13:24:54 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
#define FT_NMAP_H

#include "opts_parsing.h"

extern t_opts g_opts;

#define MIN_PORT 1
#define MAX_PORT_RANGE 1024

#define DFLT_PORT_RANGE_START 1
#define DFLT_PORT_RANGE_END 1024

typedef struct s_host_summary {
    const char *ip;
    const char *hostname;

} t_host_summary;

#endif