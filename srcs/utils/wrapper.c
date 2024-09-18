/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   wrapper.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/07 14:56:17 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 10:54:44 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <errno.h>
#include <error.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
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

void *
Malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        error(0, 0, "malloc: %s", strerror(errno));
        return (NULL);
    }
    return (ptr);
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

pcap_t *
Pcap_create(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_create(device, errbuf);
    if (handle == NULL) {
        error(0, 0, "pcap_create: %s", errbuf);
        return (NULL);
    }

    return (handle);
}

int
Pcap_activate(pcap_t *p) {
    if (pcap_activate(p) == -1) {
        error(0, 0, "pcap_activate: %s", pcap_geterr(p));
        return (1);
    }
    return (0);
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

struct addrinfo *
res_host_serv(const char *host, const char *serv, int sock_family, int sock_type) {
    int              ret   = 0;
    struct addrinfo  hints = {0};
    struct addrinfo *res   = NULL;

    hints.ai_flags    = AI_CANONNAME;
    hints.ai_family   = sock_family;
    hints.ai_socktype = sock_type;
    if ((ret = getaddrinfo(host, serv, &hints, &res)) != 0) {
        error(0, 0, "%s: %s", (host != NULL) ? host : serv, gai_strerror(ret));
        return (NULL);
    }
    return (res);
}

FILE *
Fopen(const char *path, const char *mode) {
    FILE *fd = fopen(path, mode);
    if (fd == NULL) {
        error(0, 0, "fopen: %s", strerror(errno));
        return (NULL);
    }
    return (fd);
}

ssize_t
Getline(char **lineptr, size_t *n, FILE *stream) {
    errno       = 0;
    ssize_t ret = getline(lineptr, n, stream);
    if (ret == -1 && errno != 0) {
        error(0, 0, "getline: %s", strerror(errno));
        return (-1);
    }
    return (ret);
}