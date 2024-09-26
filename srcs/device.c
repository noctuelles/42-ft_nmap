/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   device.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/26 10:45:55 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/26 15:45:12 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "device.h"

#include <string.h>

/**
 * @brief From a list of devices, get the first device that is up, running, and connected, thas has an IPv4 address.
 *
 * @param devs The list of devices.
 * @param device The device to fill with the suitable interface. This is a result parameter.
 * @param if_flags The flags that the interface must have. If if_flags is equals to 0, flags are ignored.
 * @return int 0 if a suitable interface was found, -1 otherwise.
 */
int
get_suitable_interface(pcap_if_t *devs, t_device_info *device, bpf_u_int32 if_flags) {
    for (pcap_if_t *dev = devs; dev != NULL; dev = dev->next) {
        /* Discard interface that are not up, not running, or not connected. */
        if (!(dev->flags & PCAP_IF_UP) || !(dev->flags & PCAP_IF_RUNNING) ||
            (dev->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_DISCONNECTED) {
            continue;
        }

        if (if_flags == 0 || dev->flags & if_flags) {
            for (struct pcap_addr *addr = dev->addresses; addr != NULL; addr = addr->next) {
                if (addr->addr->sa_family == AF_INET) {
                    memcpy(&device->sockaddr, addr->addr, sizeof(device->sockaddr));
                    memcpy(&device->netmask, addr->netmask, sizeof(device->netmask));
                    device->name = strdup(dev->name);
                    break;
                }
            }
        }
    }
    return (device->name == NULL ? -1 : 0);
}
