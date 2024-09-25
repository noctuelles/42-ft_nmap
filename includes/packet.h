/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/25 13:35:14 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/25 14:31:23 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PACKET_H
#define PACKET_H

#define DFT_TTL 64

#include <netinet/in.h>
#include <stdint.h>

#include "ft_nmap.h"

uint16_t get_random_ephemeral_src_port(void);
int      send_icmp_echo_request(int sock, in_addr_t src_ip, in_addr_t dst_ip, uint16_t seq);
int      send_tcp_packet(int sock, in_addr_t src_ip, in_port_t src_port, in_addr_t dst_ip, in_port_t dest_port, t_scan_type scan_type);
int      send_udp_packet(int sock_raw_fd, in_addr_t src_ip, in_port_t src_port, in_addr_t dst_ip, in_port_t dst_port);

#endif