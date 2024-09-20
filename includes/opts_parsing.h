/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   opts_parsing.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 22:50:51 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/20 17:14:34 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef OPTS_PARSING_H
#define OPTS_PARSING_H

#include <scan_engine.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct s_opts {
    int                    help;
    uint16_t               port_range[2];    /* The port range is inclusive  */
    const char            *host;             /* The host to scan */
    const char            *hosts_file_path;  /* The file containing the hosts to scan. */
    uint16_t               threads;          /* The number of threads to use for the scan */
    t_available_scans_list scans_to_perform; /* Each index */
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

extern const char *g_available_scan_types[NBR_AVAILABLE_SCANS];

#endif