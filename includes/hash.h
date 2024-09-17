/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 15:45:53 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/17 19:02:33 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef HASH_H
#define HASH_H

#include <netinet/in.h>
#include <stdint.h>

uint32_t get_syn_cookie(in_addr_t dest_ip, in_port_t dest_port, in_addr_t local_ip, in_port_t local_port, const char key[16]);

#endif