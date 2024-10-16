/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   opts.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 13:36:52 by plouvel           #+#    #+#             */
/*   Updated: 2024/10/17 13:59:02 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parsing/opts.h"

#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/utils.h"

static struct option g_long_options[] = {{"help", no_argument, NULL, 0},
                                         {"ports", required_argument, NULL, 'p'},
                                         {"host", required_argument, NULL, 'h'},
                                         {"speedup", required_argument, NULL, 'w'},
                                         {"scan", required_argument, NULL, 's'},
                                         {"file", required_argument, NULL, 'f'},
                                         {"badsum", no_argument, NULL, 'b'},
                                         {"delay", required_argument, NULL, 'd'},
                                         {"retry", required_argument, NULL, 'r'},
                                         {"spoofip", required_argument, NULL, 'S'},
                                         {NULL, 0, NULL, 0}};

t_opts g_opts = {0}; /* Program options */

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
 * @return int 0 on success, -1 if input_scan_type is invalid.
 */
static int
parse_scan_type(const char *input_scan_type, t_available_scans_list scan_list) {
    size_t scan_type_len = 0;
    size_t i             = 0;

    if (*input_scan_type == '\0') {
        error(0, 0, "you should provide at least one scan type.");
        return (-1);
    }
    while (*input_scan_type != '\0') {
        i = 0;
        while (i < NSIZE(g_available_scan_types)) {
            scan_type_len = strlen(g_available_scan_types[i]);

            if (strncmp(input_scan_type, g_available_scan_types[i], scan_type_len) == 0) {
                scan_list[i] = true;
                break;
            }
            i++;
        }
        if (i == NSIZE(g_available_scan_types)) {
            error(0, 0, "invalid scan type: '%s'.", input_scan_type);
            return (-1);
        }
        input_scan_type += scan_type_len;
        if (*input_scan_type == ',') {
            input_scan_type++;
            if (*input_scan_type == '\0') {
                error(0, 0, "trailing comma.");
                return (-1);
            }
        } else if (*input_scan_type != '\0') {
            error(0, 0, "each scan type should be separated by a comma.");
            return (-1);
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
 * @return int 0 on success, -1 if the input string is invalid.
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
    if (errno == EINVAL || errno == ERANGE || *endptr != '\0' || val < MIN_PORT || val > UINT16_MAX) {
        goto invalid_port_range;
    }
    port_range[0] = val;
    if ((token = strtok(NULL, "-")) == NULL) {
        port_range[1] = port_range[0];
        goto check;
    }
    val = strtol(token, &endptr, 10);
    if (errno == EINVAL || errno == ERANGE || *endptr != '\0' || val < MIN_PORT || val > UINT16_MAX) {
        goto invalid_port_range;
    }
    port_range[1] = val;
check:
    if (port_range[0] > port_range[1]) {
        goto invalid_port_range;
    }
    if (port_range[1] - port_range[0] >= MAX_PORT_RANGE) {
        goto max_port_exceeded;
    }
    if (port_range[0] > MAX_PORT_RANGE || port_range[1] > MAX_PORT_RANGE) {
        goto max_port_exceeded;
    }
    goto ok;
invalid_port_range:
    error(0, 0,
          "invalid port range -- should be between %u and %u (inclusive) and "
          "in the form <port1>-<port2> where port1 >= port2 OR in the form of <port1>",
          1, MAX_PORT_RANGE);
    return (-1);
max_port_exceeded:
    error(0, 0, "invalid port range -- the numbers of ports scanned cannot exceed %u OR cannot exceed %u", MAX_PORT_RANGE, MAX_PORT_RANGE);
    return (-1);
ok:
    return (0);
}

/**
 * @brief Check if the input string is a valid number and if it is in the range.
 *
 * @param str The input string.
 * @param neg If the number can be negative.
 * @param max The maximum value the number can take.
 * @param base The base of the number.
 * @param arg_rslt The result of the conversion.
 * @return int 0 on success, -1 if the input string is invalid.
 */
static int
strtol_chk(const char *str, int64_t min, int64_t max, int32_t base, long *arg_rslt) {
    char *endptr = NULL;
    long  rslt   = strtol(str, &endptr, base);

    if (errno == EINVAL || errno == ERANGE || *endptr != '\0' || rslt < min || rslt > max) {
        return (-1);
    } else {
        *arg_rslt = rslt;
    }
    return (0);
}

int
parse_opts(int argc, char **argv, t_opts *opts) {
    int  c       = 0;
    int  opt_idx = 0;
    long rslt    = 0;

    if (argc < 2) {
        error(0, 0, "too few arguments provided");
        return (-1);
    }

    /* Options default value */
    memset(g_opts.scans_to_perform, true, sizeof(g_opts.scans_to_perform));
    opts->port_range[0]   = DFLT_PORT_RANGE_START;
    opts->port_range[1]   = DFLT_PORT_RANGE_END;
    opts->threads         = DFLT_THREAD_COUNT;
    opts->host            = NULL;
    opts->hosts_file_path = NULL;
    opts->retrans_delay   = DFLT_RETRANS_DELAY;
    opts->retrans_nbr     = DFLT_RETRANS_NBR;
    opts->help            = 0;

    while ((c = getopt_long(argc, argv, "bp:h:w:s:f:r:d:S:", g_long_options, &opt_idx)) != -1) {
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
                if (strtol_chk(optarg, MIN_THREAD_COUNT, MAX_THREAD_COUNT, 10, &rslt) == -1) {
                    error(0, 0,
                          "invalid number of threads: max "
                          "%u)",
                          MAX_THREAD_COUNT);
                    return (-1);
                } else {
                    opts->threads = (uint16_t)rslt;
                }
                break;
            }
            case 's':
                memset(g_opts.scans_to_perform, false, sizeof(g_opts.scans_to_perform));
                if (parse_scan_type(optarg, opts->scans_to_perform) == -1) {
                    return (-1);
                }
                break;
            case 'p':
                if (parse_port_range(optarg, opts->port_range) == -1) {
                    return (-1);
                }
                break;
            case 'b':
                g_opts.bogus_checksum = true;
                break;
            case 'd':
                if (strtol_chk(optarg, MIN_RETRANS_DELAY, MAX_RETRANS_DELAY, 10, &rslt) == -1) {
                    error(0, 0, "invalid retransmission delay value -- should be between %u and %u.", MIN_RETRANS_DELAY, MAX_RETRANS_DELAY);
                    return (-1);
                }
                g_opts.retrans_delay = (uint16_t)rslt;
                break;
            case 'r':
                if (strtol_chk(optarg, MIN_RETRANS_NBR, MAX_RETRANS_NBR, 10, &rslt) == -1) {
                    error(0, 0, "invalid retransmission value -- should be between %u and %u.", MIN_RETRANS_NBR, MAX_RETRANS_NBR);
                    return (-1);
                }
                g_opts.retrans_nbr = (uint8_t)rslt;
                break;
            case 'S':
                if (inet_pton(AF_INET, optarg, &opts->spoof_ip) == 0) {
                    error(0, 0, "invalid IP address: %s", optarg);
                    return (-1);
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
