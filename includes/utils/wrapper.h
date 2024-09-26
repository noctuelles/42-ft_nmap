/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   wrapper.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/07 15:53:45 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/18 10:55:15 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef WRAPPER_H
#define WRAPPER_H

#include "pcap.h"

/* Libpcap wrapper */

int     Pcap_findalldevs(pcap_if_t **alldevsp);
pcap_t *Pcap_create(const char *device);
pcap_t *Pcap_open_live(const char *device, int snaplen, int promisc, int to_ms);
int     Pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
int     Pcap_setfilter(pcap_t *p, struct bpf_program *fp);
int     Pcap_activate(pcap_t *p);

/* Libc wrapper */

int              Socket(int domain, int type, int protocol);
ssize_t          Sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
struct addrinfo *res_host_serv(const char *host, const char *serv, int sock_family, int sock_type);
FILE            *Fopen(const char *path, const char *mode);
ssize_t          Getline(char **lineptr, size_t *n, FILE *stream);
void            *Malloc(size_t size);

#endif