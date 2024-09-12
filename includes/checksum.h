/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   checksum.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/12 13:00:32 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/12 13:01:50 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

uint16_t compute_tcphdr_checksum(in_addr_t source_ip, in_addr_t dest_ip, struct tcphdr tcphdr, uint8_t *tcp_data, size_t tcp_data_len);
uint16_t compute_udphdr_checksum(in_addr_t source_ip, in_addr_t dest_ip, struct udphdr udphdr, uint8_t *udp_data, size_t udp_data_len);

#endif