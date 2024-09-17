/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/17 15:21:58 by plouvel           #+#    #+#             */
/*   Updated: 2024/09/17 19:02:33 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

#define _le64toh(x) ((uint64_t)(x))

#define ROTATE(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define HALF_ROUND(a, b, c, d, s, t) \
    a += b;                          \
    c += d;                          \
    b = ROTATE(b, s) ^ a;            \
    d = ROTATE(d, t) ^ c;            \
    a = ROTATE(a, 32);

#define DOUBLE_ROUND(v0, v1, v2, v3)    \
    HALF_ROUND(v0, v1, v2, v3, 13, 16); \
    HALF_ROUND(v2, v1, v0, v3, 17, 21); \
    HALF_ROUND(v0, v1, v2, v3, 13, 16); \
    HALF_ROUND(v2, v1, v0, v3, 17, 21);

/**
 * @brief SipHash 24 Algorithm
 *
 * @param src Data source.
 * @param src_sz Data size, in bytes.
 * @param key 128 bits key.
 * @return uint64_t Resulting hash.
 */
static uint64_t
siphash24(const void *src, unsigned long src_sz, const char key[16]) {
    const uint64_t *_key = (uint64_t *)key;
    uint64_t        k0   = _le64toh(_key[0]);
    uint64_t        k1   = _le64toh(_key[1]);
    uint64_t        b    = (uint64_t)src_sz << 56;
    const uint64_t *in   = (uint64_t *)src;

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    while (src_sz >= 8) {
        uint64_t mi = _le64toh(*in);
        in += 1;
        src_sz -= 8;
        v3 ^= mi;
        DOUBLE_ROUND(v0, v1, v2, v3);
        v0 ^= mi;
    }

    uint64_t t  = 0;
    uint8_t *pt = (uint8_t *)&t;
    uint8_t *m  = (uint8_t *)in;
    switch (src_sz) {
        case 7:
            pt[6] = m[6];
            // fall through
        case 6:
            pt[5] = m[5];
            // fall through
        case 5:
            pt[4] = m[4];
            // fall through
        case 4:
            *((uint32_t *)&pt[0]) = *((uint32_t *)&m[0]);
            break;
        case 3:
            pt[2] = m[2];
            // fall through
        case 2:
            pt[1] = m[1];
            // fall through
        case 1:
            pt[0] = m[0];
    }
    b |= _le64toh(t);

    v3 ^= b;
    DOUBLE_ROUND(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    DOUBLE_ROUND(v0, v1, v2, v3);
    DOUBLE_ROUND(v0, v1, v2, v3);
    return (v0 ^ v1) ^ (v2 ^ v3);
}

uint32_t
get_syn_cookie(in_addr_t dest_ip, in_port_t dest_port, in_addr_t local_ip, in_port_t local_port, const char key[16]) {
    uint8_t data[12];

    *((uint32_t *)&data[0])  = local_ip;
    *((uint32_t *)&data[4])  = dest_ip;
    *((uint16_t *)&data[8])  = local_port;
    *((uint16_t *)&data[10]) = dest_port;

    return ((uint32_t)(siphash24(data, sizeof(data), key) & 0xFFFFFFFF));
}