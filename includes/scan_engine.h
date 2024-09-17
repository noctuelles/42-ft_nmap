/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan_engine.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 16:50:59 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/17 16:52:00 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SCAN_ENGINE_H
#define SCAN_ENGINE_H

typedef enum s_scan_type { /* TCP Scan */ SYN_SCAN, NULL_SCAN, FIN_SCAN, XMAS_SCAN, ACK_SCAN, /* UDP Scan */ UDP_SCAN } t_scan_type;

#endif