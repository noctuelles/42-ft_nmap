/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/01 16:56:30 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/06 13:51:18 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pcap.h"

// We can never read UDP or TCP packets using a raw socket (Section 28.4) (UNIX
// Network Programming, Volume 1, Third Edition)

// https://stackoverflow.com/a/39683934
// man 7 raw
// man 7 socket

int
main(int argc, char **argv) {
    (void)argc, (void)argv;
    int                 sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    struct iphdr        iphdr;
    char                errbuf[PCAP_ERRBUF_SIZE];
    struct sockaddr_in *local;
    pcap_if_t          *devs;
    const char *ip = "142.250.201.174";  // As of 5th September 2024, this point
                                         // to a google IP address.

    if (sock < 0) {
        perror("socket");
        return 1;
    }
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt");
        return 1;
    }
    if (pcap_findalldevs(&devs, errbuf) < 0) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    if (!devs) {
        fprintf(stderr, "No devices found\n");
        return 1;
    }
    for (pcap_addr_t *addr = devs->addresses; addr; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            local = (struct sockaddr_in *)addr->addr;
            break;
        }
    }
    if (!local) {
        fprintf(stderr, "No IPv4 address found on first interface\n");
        return 1;
    }
    srand(time(NULL));

    iphdr.saddr    = local->sin_addr.s_addr;
    iphdr.daddr    = inet_addr(ip);
    iphdr.protocol = IPPROTO_TCP;
    iphdr.ihl      = 5;
    iphdr.version  = IPVERSION;
    iphdr.ttl      = 64;
    iphdr.tos      = 0;
    iphdr.frag_off = 0;
    iphdr.id    = 0; /* The kernel will fill out this field (see man 7 raw). */
    iphdr.check = 0; /* The kernel will fill out this field (see man 7 raw). */

    struct sockaddr_in send;
    struct tcphdr      tcphdr;
    /* See
     * https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml*/
    const uint16_t ephemeral_port_start = 49152;
    const uint16_t ephemeral_port_end   = 65535;

    tcphdr.source = htons(rand() % (ephemeral_port_end - ephemeral_port_start) +
                          ephemeral_port_start);
    tcphdr.dest   = htons(80);
    tcphdr.syn    = 1;
    tcphdr.seq    = htons(rand());
    tcphdr.ack    = 0;
    tcphdr.window = htons(1024);
    tcphdr.check =
        0; /* This is not right. We should compute the checksum ourself. */
    tcphdr.doff = 5;
    /* This TCP Header is probably very incomplete. This program is just a
     * tracer bullet. */

    uint8_t *packet = malloc(sizeof(iphdr) + sizeof(tcphdr));

    memcpy(packet, &iphdr, sizeof(iphdr));
    memcpy(packet + sizeof(iphdr), &tcphdr, sizeof(tcphdr));

    /* This looks redondant, since we craft the IP header ourselves (why we
     * could need to specify the destination address ?)
     * (https://stackoverflow.com/questions/39682988/purpose-of-sendto-address-for-c-raw-socket)
     * The destination address is still needed for the kernel to route the
     * packet. It will not modify the IP header we crafted !
     */
    send.sin_family      = AF_INET;
    send.sin_addr.s_addr = iphdr.daddr;
    if (sendto(sock, packet, sizeof(iphdr) + sizeof(tcphdr), 0,
               (const struct sockaddr *)&send, sizeof(send)) < 0) {
        perror("sendto");
        return 1;
    }
    return 0;
}