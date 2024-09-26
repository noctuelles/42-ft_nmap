/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   device.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/26 10:46:26 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/26 10:53:14 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef DEVICE_H
#define DEVICE_H

#include "pcap.h"

typedef struct s_device_info {
    char              *name;
    struct sockaddr_in sockaddr;
    struct sockaddr_in netmask;
} t_device_info;

int get_suitable_interface(pcap_if_t *devs, t_device_info *device, bpf_u_int32 if_flags);

#endif