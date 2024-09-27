/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/27 14:55:38 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/27 14:59:31 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PRINT_H
#define PRINT_H

#include "ft_nmap.h"

void print_usage(void);
void print_intro(const t_ft_nmap *ft_nmap);
void print_results(const t_ft_nmap *ft_nmap);

#endif