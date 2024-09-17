# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: plouvel <plouvel@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/09/01 17:00:47 by plouvel           #+#    #+#              #
#    Updated: 2024/09/17 15:47:43 by plouvel          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

LIBPCAP_DIR=libpcap
LIBFT_DIR=libft

SRCS_DIR=srcs
OBJS_DIR=objs
INCS_DIR=includes

SRCS=main.c \
    parsing/ip.c \
	parsing/opts.c \
	utils/wrapper.c \
	queue.c \
	hash.c \
	checksum.c

OBJS=$(addprefix $(OBJS_DIR)/, $(SRCS:.c=.o))

NAME=ft_nmap
CFLAGS=-Wall -Wextra -Werror -Wpedantic -g3 -std=gnu11
CC=gcc
RM=rm -rf

LIBPCAP = $(LIBPCAP_DIR)/libpcap.a
LIBFT   = $(LIBFT_DIR)/libft.a

all: $(NAME)

$(NAME): $(OBJS) $(LIBPCAP) $(LIBFT)
	$(CC) -o $(NAME) $(OBJS) -L $(LIBPCAP_DIR) -lpcap -L $(LIBFT_DIR) -lft
	sudo setcap cap_net_raw,cap_net_admin=eip $(NAME)

$(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I $(INCS_DIR) -I $(LIBPCAP_DIR) -I $(LIBFT_DIR)/includes -c $< -o $@

$(LIBPCAP):
	cd libpcap && \
	./autogen.sh && \
	./configure && \
	make

$(LIBFT):
	make -C $(LIBFT_DIR)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

vm-up:
	cd tests/e2e && \
	vagrant up

re: fclean all

.PHONY: all clean fclean re vm-up