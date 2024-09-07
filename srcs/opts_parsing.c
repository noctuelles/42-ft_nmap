/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   opts_parsing.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 22:50:21 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/07 14:41:02 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "opts_parsing.h"

#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

static const char *g_available_scan_types[] = {"SYN", "NULL", "FIN", "XMAS", "ACK", "UDP"};

static struct option g_long_options[] = {{"help", no_argument, NULL, 0},
                                         {"ports", required_argument, NULL, 'p'},
                                         {"host", required_argument, NULL, 'h'},
                                         {"speedup", required_argument, NULL, 'w'},
                                         {"scan", required_argument, NULL, 's'},
                                         {"file", required_argument, NULL, 'f'},
                                         {NULL, 0, NULL, 0}};

/**
 * @brief Parse the scan type from the input string and set the corresponding
 * bit in the scan_type_mask. In order to be valid, the input string should be a
 * comma separated list of scan types. Available scan types are defined in the
 * g_available_scan_types variable.
 *
 * @note The scan type mask is a 64 bit integer where the first 6 bits are used
 * to set the SYN, NULL, FIN, XMAS, ACK, UDP.
 *
 * @param input_scan_type The comma separated list of scan types.
 * @param scan_type_mask The mask to set the scan types.
 * @return int 0 on success, 1 if input_scan_type is invalid.
 */
static int
parse_scan_type(const char *input_scan_type, uint64_t *scan_type_mask) {
    size_t scan_type_len = 0;
    size_t i             = 0;

    if (*input_scan_type == '\0') {
        error(0, 0, "you should provide at least one scan type");
        return (1);
    }
    while (*input_scan_type != '\0') {
        i = 0;
        while (i < NSIZE(g_available_scan_types)) {
            scan_type_len = strlen(g_available_scan_types[i]);

            if (strncmp(input_scan_type, g_available_scan_types[i], scan_type_len) == 0) {
                SET_BIT(*scan_type_mask, i);
                break;
            }
            i++;
        }
        if (i == NSIZE(g_available_scan_types)) {
            error(0, 0, "invalid scan type: %s", input_scan_type);
            return (1);
        }
        input_scan_type += scan_type_len;
        if (*input_scan_type == ',') {
            input_scan_type++;
            if (*input_scan_type == '\0') {
                error(0, 0, "trailing comma");
                return (1);
            }
        } else if (*input_scan_type != '\0') {
            error(0, 0, "each scan type should be separated by a comma");
            return (1);
        }
    }
    return (0);
}

/**
 * @brief Parse the port range from the input string and set the corresponding
 * port_range array. The input string should be in the form of "start-end" where
 * start and end are the port range. The port range is inclusive.
 *
 * @note The subject enforce the port range to be between 1 and 1024
 * (inclusive).
 *
 * @param input_port_range The input string containing the port range.
 * @param port_range The port range array to set.
 * @return int 0 on success, 1 if the input string is invalid.
 */
static int
parse_port_range(const char *input_port_range, uint16_t port_range[2]) {
    char *endptr = NULL;
    char *token  = strtok((char *)input_port_range, "-");
    long  val    = 0;

    if (token == NULL) {
        goto invalid_port_range;
    }
    val = strtol(token, &endptr, 10);
    if (errno == EINVAL || errno == ERANGE || *endptr != '\0' || val < MIN_PORT || val > MAX_PORT) {
        goto invalid_port_range;
    }
    port_range[0] = val;
    if ((token = strtok(NULL, "-")) == NULL) {
        goto invalid_port_range;
    }
    val = strtol(token, &endptr, 10);
    if (errno == EINVAL || errno == ERANGE || *endptr != '\0' || val < MIN_PORT || val > MAX_PORT) {
        goto invalid_port_range;
    }
    port_range[1] = val;
    if (port_range[0] > port_range[1]) {
        goto invalid_port_range;
    }
    goto ok;
invalid_port_range:
    error(0, 0,
          "invalid port range -- should be between %u and %u (inclusive) and "
          "in the form <port>-<port>",
          MIN_PORT, MAX_PORT);
    return (1);
ok:
    return (0);
}

int
parse_opts(int argc, char **argv, t_opts *opts) {
    int c       = 0;
    int opt_idx = 0;

    if (argc < 2) {
        error(0, 0, "too few arguments provided");
        return (1);
    }

    /* Options default value */
    opts->scan_type       = 64U; /* 64 is 0b111111, so all the scans are enabled by default. */
    opts->port_range[0]   = MIN_PORT;
    opts->port_range[1]   = MAX_PORT;
    opts->threads         = 0;
    opts->host            = NULL;
    opts->hosts_file_path = NULL;
    opts->help            = 0;

    while ((c = getopt_long(argc, argv, "p:h:w:s:f:", g_long_options, &opt_idx)) != -1) {
        switch (c) {
            case 0:
                if (strcmp(g_long_options[opt_idx].name, "help") == 0) {
                    opts->help = 1;
                }
                break;
            case 'f':
                opts->hosts_file_path = optarg;
                break;
            case 'h':
                opts->host = optarg;
                break;
            case 'w': {
                char *endptr = NULL;
                long  rslt   = strtol(optarg, &endptr, 10);

                if (errno == EINVAL || errno == ERANGE || *endptr != '\0' || rslt < 0 || rslt > MAX_THREAD_COUNT) {
                    error(0, 0,
                          "invalid number of threads: max "
                          "%u)",
                          MAX_THREAD_COUNT);
                    return (1);
                } else {
                    opts->threads = (uint16_t)rslt;
                }
                break;
            }
            case 's':
                if (parse_scan_type(optarg, &opts->scan_type) == 1) {
                    return (1);
                }
                break;
            case 'p':
                if (parse_port_range(optarg, opts->port_range) == 1) {
                    return (1);
                }
                break;
            case '?':
                break;
            default:
                break;
        }
    }
    return (0);
}
