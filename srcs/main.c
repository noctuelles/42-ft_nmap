/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/01 16:56:30 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/01 17:12:48 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>

#include "pcap.h"

int
main(int argc, char **argv) {
    (void)argc, (void)argv;
    pcap_if_t *pcap_if;
    char       error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

    if (pcap_findalldevs(&pcap_if, error_buffer) == PCAP_ERROR) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }
    if (pcap_if == NULL) {
        puts("No network device found.");
    } else {
        printf("Network device found: %s\n", pcap_if->name);
    }
    return 0;
}