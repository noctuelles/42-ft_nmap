# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/09/01 17:00:47 by plouvel           #+#    #+#              #
#    Updated: 2024/09/06 22:59:13 by plouvel          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

LIBPCAP_DIR=libpcap
SRCS_DIR=srcs
OBJS_DIR=objs
INCS_DIR=includes

SRCS=main.c \
    opts_parsing.c

OBJS=$(addprefix $(OBJS_DIR)/, $(SRCS:.c=.o))

NAME=ft_nmap
CFLAGS=-Wall -Wextra -Werror -Wpedantic -g3
CC=gcc
RM=rm -rf

LIBPCAP = $(LIBPCAP_DIR)/libpcap.a

all: $(NAME)

$(NAME): $(OBJS) $(LIBPCAP)
	$(CC) -o $(NAME) $(OBJS) -L $(LIBPCAP_DIR) -lpcap

$(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c
	$(CC) $(CFLAGS) -I $(INCS_DIR) -I $(LIBPCAP_DIR) -c $< -o $@

$(LIBPCAP):
	cd libpcap && \
	./autogen.sh && \
	./configure && \
	make

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re