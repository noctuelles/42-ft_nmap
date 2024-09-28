/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   opts.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 22:50:51 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/28 21:21:14 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PARSING_OPTS_H
#define PARSING_OPTS_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "scan_engine.h"

typedef struct s_opts {
    int                    help;
    uint16_t               port_range[2];    /* The port range is inclusive  */
    const char            *host;             /* The host to scan */
    const char            *hosts_file_path;  /* The file containing the hosts to scan. */
    uint16_t               threads;          /* The number of threads to use for the scan */
    uint8_t                retrans_nbr;      /* The number of retransmissions before giving up on a probe. */
    uint16_t               retrans_delay;    /* The delay between each retransmission in milliseconds. */
    struct in_addr         spoof_ip;         /* The IP address of the interface you wish to send packets through. */
    bool                   bogus_checksum;   /* Alter the checksum. */
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

extern t_opts g_opts;

#endif