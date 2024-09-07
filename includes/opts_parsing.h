/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   opts_parsing.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 22:50:51 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/07 14:32:07 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef OPTS_PARSING_H
#define OPTS_PARSING_H

#include <stdint.h>

#define MIN_PORT 1
#define MAX_PORT 1024

#define MAX_THREAD_COUNT 250

typedef struct s_opts {
    int         help;
    uint16_t    port_range[2];   /* The port range is inclusive  */
    const char *host;            /* The host to scan */
    const char *hosts_file_path; /* The file containing the hosts to scan. */
    uint16_t    threads;         /* The number of threads to use for the scan */
    uint64_t    scan_type;       /* The type of scan to perform. The first 6 bit are used to
                                   set the SYN, NULL, FIN, XMAS, ACK, UDP respectively. */
} t_opts;

/**
 * @brief Parse the command line options and set the corresponding fields in the opts structure.
 *
 * @param argc The number of arguments.
 * @param argv The arguments.
 * @param opts The options structure to fill.
 * @return int 0 on success, 1 on error.
 */
int parse_opts(int argc, char **argv, t_opts *opts);

#endif