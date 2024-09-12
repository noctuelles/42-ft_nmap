/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tcp.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 14:31:52 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/12 11:25:47 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "tcp.h"

#include <assert.h>
#include <string.h>

/* https://datatracker.ietf.org/doc/html/rfc9293#section-3.1-6.18.1 */
typedef struct s_pseudo_tcphdr {
    in_addr_t source; /* IPv4 source address in network byte order. */
    in_addr_t dest;   /* IPv4 dest address in network byte order. */
    uint8_t   zero;   /* Bits set to zero. */
    uint8_t   ptcl;   /* The protocol number from the IP header. */
    // clang-format off
    uint16_t  tcplen; /* The TCP header length plus the data length in octets (this is not an explicitly transmitted quantity but is computed), and it does not count the 12 octets of the pseudo-header. */
    // clang-format on
} t_pseudo_tcphdr;

/**
 * @brief Compute the internet checksum of a buffer.
 *
 * @param data The buffer to compute the checksum from.
 * @param len The length of the buffer in bytes.
 * @return uint16_t The computed checksum.
 *
 * @note See https://datatracker.ietf.org/doc/html/rfc1071. 64-bit words for summing are used for performance reasons.
 */
static uint16_t
compute_internet_checksum(uint8_t *data, size_t len) {
    register uint64_t sum   = 0;
    uint64_t         *words = (uint64_t *)data;

    while (len > 1) {
        sum += *words++;
        len -= 4;
    }
    if (len > 0) {
        sum += *(uint8_t *)words;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/**
 * @brief
 *
 * @param tcphdr
 * @param iphdr
 * @param tcp_data_len
 */
uint16_t
compute_tcphdr_checksum(const struct ip *iphdr, struct tcphdr tcphdr, uint8_t *tcp_data, size_t tcp_data_len) {
    uint8_t         buffer[IP_MAXPACKET];
    t_pseudo_tcphdr pseudo_tcphdr = {
        .source = iphdr->ip_src.s_addr,
        .dest   = iphdr->ip_dst.s_addr,
        .zero   = 0,
        .ptcl   = iphdr->ip_p,
        .tcplen = htons(tcphdr.th_off * 4 + tcp_data_len),
    };

    tcphdr.th_sum = 0; /* An internet checksum is always computed by setting the checksum field to 0. */

    memcpy(buffer, &pseudo_tcphdr, sizeof(pseudo_tcphdr));
    memcpy(buffer + sizeof(pseudo_tcphdr), &tcphdr, tcphdr.th_off * 4);
    memcpy(buffer + sizeof(pseudo_tcphdr) + tcphdr.th_off * 4, tcp_data, tcp_data_len);

    return (compute_internet_checksum(buffer, sizeof(pseudo_tcphdr) + tcphdr.th_off * 4 + tcp_data_len));
}