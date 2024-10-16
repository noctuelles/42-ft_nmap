/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hosts.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/10 13:36:40 by plouvel           #+#    #+#             */
/*   Updated: 2024/10/16 17:47:06 by plouvel          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "parsing/hosts.h"

#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

#include "libft.h"
#include "utils/wrapper.h"

static t_list *
new_resv_host_node(struct addrinfo *res) {
    t_resv_host *resv_host = NULL;
    t_list      *new_node  = NULL;

    if ((resv_host = Malloc(sizeof(t_resv_host))) == NULL) {
        return (NULL);
    }
    memset(resv_host, 0, sizeof(*resv_host));
    memcpy(&resv_host->sockaddr, res->ai_addr, res->ai_addrlen);
    if (res->ai_canonname == NULL) {
        resv_host->hostname = NULL;
    } else {
        if ((resv_host->hostname = strdup(res->ai_canonname)) == NULL) {
            free(resv_host);
            return (NULL);
        }
    }
    if ((new_node = ft_lstnew(resv_host)) == NULL) {
        free_resv_host(resv_host);
        return (NULL);
    }
    return (new_node);
}

void
free_resv_host(void *content) {
    t_resv_host *resv_host = (t_resv_host *)content;

    free(resv_host->hostname);
    free(resv_host);
}

/**
 * @brief Parse the host from a given file.
 *
 * @param filepath The file containing the hosts.
 * @return t_list* The list of t_resv_host, or NULL on error.
 */
t_list *
parse_host_from_file(const char *filepath) {
    FILE            *file     = NULL;
    char            *line     = NULL;
    char            *new_line = NULL;
    size_t           len      = 0;
    struct addrinfo *res      = NULL;
    t_list          *new_node = NULL;
    t_list          *list     = NULL;

    if ((file = Fopen(filepath, "r")) == NULL) {
        return (NULL);
    }
    while (Getline(&line, &len, file) != -1) {
        if ((new_line = strrchr(line, '\n')) != NULL) { /* Remove trailing newline */
            *new_line = '\0';
        }
        if (*line == '\0') { /* Skip blank lines */
            continue;
        }
        if ((res = res_host_serv(line, NULL, AF_INET, SOCK_RAW)) == NULL) {
            goto err_clean;
        }
        if ((new_node = new_resv_host_node(res)) == NULL) {
            goto err_clean;
        }
        ft_lstadd_back(&list, new_node);
        freeaddrinfo(res), res = NULL;
    }
    if (errno != 0) { /* If getline failed for other reason than EOF, errno should not be 0. */
        goto err_clean;
    }
    goto clean;
err_clean:
    ft_lstclear(&list, free_resv_host);
clean:
    (void)fclose(file);
    freeaddrinfo(res);
    free(line);
    return (list);
}

/**
 * @brief Parse host from a given string.
 *
 * @param str The string containing the host.
 * @return t_list* The list containing a single t_resv_host, or NULL on error.
 */
t_list *
parse_host_from_str(const char *str) {
    struct addrinfo *res      = NULL;
    t_list          *new_node = NULL;
    t_list          *list     = NULL;

    if ((res = res_host_serv(str, NULL, AF_INET, SOCK_RAW)) == NULL) {
        return (NULL);
    }
    if ((new_node = new_resv_host_node(res)) == NULL) {
        freeaddrinfo(res);
        return (NULL);
    }
    ft_lstadd_back(&list, new_node);
    freeaddrinfo(res);
    return (list);
}