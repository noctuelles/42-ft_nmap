/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/07 14:31:31 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/07 14:32:14 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef UTILS_H
#define UTILS_H

#define NSIZE(x) (sizeof(x) / sizeof(x[0]))
#define GET_BIT(n, i) ((n >> i) & 1)
#define SET_BIT(n, i) (n |= 1 << i)

#endif
