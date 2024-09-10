/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   wrapper.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/07 14:56:17 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/07 15:57:51 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <errno.h>
#include <error.h>
#include <string.h>
#include <sys/socket.h>

#include "pcap.h"

/**
 * @brief This file is a wrapper for functions that can fail. It just simply prints an error message.
 *
 */

int
Pcap_findalldevs(pcap_if_t **alldevsp) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(alldevsp, errbuf) == -1) {
        error(0, 0, "pcap_findalldevs: %s", errbuf);
        return (1);
    }
    return (0);
}

pcap_t *
Pcap_open_live(const char *device, int snaplen, int promisc, int to_ms) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
    if (handle == NULL) {
        error(0, 0, "pcap_open_live: %s", errbuf);
        return (NULL);
    }
    return (handle);
}

int
Pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask) {
    if (pcap_compile(p, fp, str, optimize, netmask) == -1) {
        error(0, 0, "pcap_compile: %s", pcap_geterr(p));
        return (1);
    }
    return (0);
}

int
Pcap_setfilter(pcap_t *p, struct bpf_program *fp) {
    if (pcap_setfilter(p, fp) == -1) {
        error(0, 0, "pcap_setfilter: %s", pcap_geterr(p));
        return (1);
    }
    return (0);
}

int
Socket(int domain, int type, int protocol) {
    int fd = socket(domain, type, protocol);
    if (fd == -1) {
        error(0, 0, "socket: %s", strerror(errno));
        return (-1);
    }
    return (fd);
}

ssize_t
Sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    ssize_t ret = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    if (ret == -1) {
        error(0, 0, "sendto: %s", strerror(errno));
        return (-1);
    }
    return (ret);
}