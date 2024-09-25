/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   opts_parsing.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 22:50:51 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/25 14:26:29 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef OPTS_PARSING_H
#define OPTS_PARSING_H

#include <scan_engine.h>
#include <stdbool.h>
#include <stdint.h>

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