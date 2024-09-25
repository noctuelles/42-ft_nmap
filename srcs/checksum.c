/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   checksum.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 14:31:52 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/25 14:15:26 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "checksum.h"

#include <string.h>

/* https://datatracker.ietf.org/doc/html/rfc9293#section-3.1-6.18.1 */
typedef struct s_pseudo_hdr {
    in_addr_t source; /* IPv4 source address in network byte order. */
    in_addr_t dest;   /* IPv4 dest address in network byte order. */
    uint8_t   zero;   /* Bits set to zero. */
    uint8_t   ptcl;   /* The protocol number from the IP header. */
    // clang-format off
    uint16_t  tcplen; /* The TCP/UDP header length plus the data length in octets (this is not an explicitly transmitted quantity but is computed), and it does not count the 12 octets of the pseudo-header. */
    // clang-format on
} t_pseudo_hdr;

/**
 * @brief Compute the internet checksum of a buffer.
 *
 * @param data The buffer to compute the checksum from.
 * @param len The length of the buffer in bytes.
 * @return uint16_t The computed checksum.
 *
 * @note See https://datatracker.ietf.org/doc/html/rfc1071
 */
static uint16_t
compute_internet_checksum(uint8_t *data, size_t len) {
    register uint32_t sum = 0;

    while (len > 1) {
        sum += *(uint16_t *)data;
        len -= 2;
        data += 2;
    }
    if (len > 0) {
        sum += *data;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/**
 * @brief Compute the checksum of a TCP header under IPv4.
 *
 * @param source_ip Source IP address in network byte order.
 * @param dest_ip Destination IP address in network byte order.
 * @param tcphdr The TCP header to compute the checksum from.
 * @param tcp_data The TCP data to compute the checksum from.
 * @param tcp_data_len The length of the TCP data in bytes.
 * @return uint16_t The computed checksum.
 */
uint16_t
compute_tcphdr_checksum(in_addr_t source_ip, in_addr_t dest_ip, struct tcphdr tcphdr, void *tcp_data, size_t tcp_data_len) {
    uint8_t      buffer[IP_MAXPACKET];
    t_pseudo_hdr pseudo_tcphdr = {
        .source = source_ip,
        .dest   = dest_ip,
        .zero   = 0,
        .ptcl   = IPPROTO_TCP,
        .tcplen = htons(tcphdr.doff * 4 + tcp_data_len),
    };

    tcphdr.check = 0; /* An internet checksum is always computed by setting the checksum field to 0. */

    memcpy(buffer, &pseudo_tcphdr, sizeof(pseudo_tcphdr));
    memcpy(buffer + sizeof(pseudo_tcphdr), &tcphdr, tcphdr.doff * 4);
    memcpy(buffer + sizeof(pseudo_tcphdr) + tcphdr.doff * 4, tcp_data, tcp_data_len);

    return (compute_internet_checksum(buffer, sizeof(pseudo_tcphdr) + tcphdr.doff * 4 + tcp_data_len));
}

/**
 * @brief Compute the checksum of a UDP header under IPv4.
 *
 * @param source_ip Source IP address in network byte order.
 * @param dest_ip Destination IP address in network byte order.
 * @param udphdr The UDP header to compute the checksum from.
 * @param udp_data The UDP data to compute the checksum from.
 * @param udp_data_len The length of the UDP data in bytes.
 * @return uint16_t The computed checksum.
 */
uint16_t
compute_udphdr_checksum(in_addr_t source_ip, in_addr_t dest_ip, struct udphdr udphdr, void *udp_data, size_t udp_data_len) {
    uint8_t      buffer[IP_MAXPACKET];
    t_pseudo_hdr pseudo_udphdr = {
        .source = source_ip,
        .dest   = dest_ip,
        .zero   = 0,
        .ptcl   = IPPROTO_UDP,
        .tcplen = htons(sizeof(udphdr) + udp_data_len),
    };

    udphdr.check = 0; /* An internet checksum is always computed by setting the checksum field to 0. */

    memcpy(buffer, &pseudo_udphdr, sizeof(pseudo_udphdr));
    memcpy(buffer + sizeof(pseudo_udphdr), &udphdr, sizeof(udphdr));
    memcpy(buffer + sizeof(pseudo_udphdr) + sizeof(udphdr), udp_data, udp_data_len);

    return (compute_internet_checksum(buffer, sizeof(pseudo_udphdr) + sizeof(udphdr) + udp_data_len));
}

/**
 * @brief Compute the checksum of an ICMP header under IPv4.
 *
 * @param icmphdr The ICMP header to compute the checksum from.
 * @param icmpdata The ICMP data to compute the checksum from.
 * @param icmp_data_len The length of the ICMP data in bytes.
 * @return uint16_t The computed checksum.
 */
uint16_t
compute_imcphdr_checksum(struct icmphdr icmphdr, void *icmpdata, size_t icmp_data_len) {
    uint8_t buffer[IP_MAXPACKET];

    icmphdr.checksum = 0;

    memcpy(buffer, &icmphdr, sizeof(icmphdr));
    memcpy(buffer + sizeof(icmphdr), icmpdata, icmp_data_len);

    return (compute_internet_checksum(buffer, sizeof(icmphdr) + icmp_data_len));
}