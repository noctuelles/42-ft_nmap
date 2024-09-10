/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   tcp.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 14:31:52 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/10 14:58:14 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "tcp.h"

/* https://datatracker.ietf.org/doc/html/rfc9293#section-3.1-6.18.1 */
typedef struct s_pseudo_tcphdr {
    in_addr_t source;   /* IPv4 source address in network byte order. */
    in_addr_t dest;     /* IPv4 dest address in network byte order. */
    uint32_t  zero : 8; /* Bits set to zero. */
    uint32_t  ptcl : 8; /* The protocol number from the IP header. */
    // clang-format off
    uint32_t  tcplen : 16; /* The TCP header length plus the data length in octets (this is not an explicitly transmitted quantity but is computed), and it does not count the 12 octets of the pseudo-header. */
    // clang-format on
} t_pseudo_tcphdr;

struct s_tcp_packet {
    struct ip     iphdr;
    struct tcphdr tcphdr;
    uint8_t       tcp_data[];
};

/**
 * @brief
 *
 * @param tcphdr
 * @param iphdr
 * @param tcp_data_len
 */
void
compute_tcphdr_checksum(const struct ip *iphdr, struct tcphdr *tcphdr, size_t tcp_data_len) {
    t_pseudo_tcphdr pseudo_tcphdr = {
        .source = iphdr->ip_src.s_addr,
        .dest   = iphdr->ip_dst.s_addr,
        .zero   = 0,
        .ptcl   = iphdr->ip_p,
        .tcplen = htons(tcphdr->th_off * 4 + tcp_data_len),
    };

    tcphdr->th_sum = 0;
}