/*
 * umbim
 * Copyright (C) 2014 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <libubox/uloop.h>

#include "mbim.h"

uint8_t mbim_buffer[MBIM_BUFFER_SIZE];
static struct uloop_fd mbim_fd;
static uint32_t expected;
int no_close;

static void mbim_msg_tout_cb(struct uloop_timeout *t)
{
	fprintf(stderr, "ERROR: mbim message timeout\n");
	uloop_end();
}

static struct uloop_timeout tout = {
	.cb = mbim_msg_tout_cb,
};

int
mbim_send(void)
{
	struct mbim_message_header *hdr = (struct mbim_message_header *) mbim_buffer;
	int ret = 0;

	if (le32toh(hdr->length) > MBIM_BUFFER_SIZE) {
		fprintf(stderr, "message too big %d\n", le32toh(hdr->length));
		return -1;
	}

	if (verbose) {
		fprintf(stderr, "sending (%d): ", le32toh(hdr->length));
		for (ret = 0; ret < le32toh(hdr->length); ret++)
			printf("%02x ", ((uint8_t *) mbim_buffer)[ret]);
		printf("\n");
		printf("  header_type: %04X\n", le32toh(hdr->type));
		printf("  header_length: %04X\n", le32toh(hdr->length));
		printf("  header_transaction: %04X\n", le32toh(hdr->transaction_id));
	}

	ret = write(mbim_fd.fd, mbim_buffer, le32toh(hdr->length));
	if (!ret) {
		perror("writing data failed: ");
	} else {
		expected = le32toh(hdr->type) | 0x80000000;
		uloop_timeout_set(&tout, 15000);
	}
	return ret;
}

static void
mbim_recv(struct uloop_fd *u, unsigned int events)
{
	ssize_t cnt = read(u->fd, mbim_buffer, MBIM_BUFFER_SIZE);
	struct mbim_message_header *hdr = (struct mbim_message_header *) mbim_buffer;
	struct command_message *msg = (struct command_message *) mbim_buffer;
	int i;

	if (cnt < 0)
		return;

	if (cnt < sizeof(struct mbim_message_header)) {
		perror("failed to read() data: ");
		return;
	}
	if (verbose) {
		printf("reading (%zu): ", cnt);
		for (i = 0; i < cnt; i++)
			printf("%02x ", mbim_buffer[i]);
		printf("\n");
		printf("  header_type: %04X\n", le32toh(hdr->type));
		printf("  header_length: %04X\n", le32toh(hdr->length));
		printf("  header_transaction: %04X\n", le32toh(hdr->transaction_id));
	}

	if (le32toh(hdr->type) == expected)
		uloop_timeout_cancel(&tout);

	switch(le32toh(hdr->type)) {
	case MBIM_MESSAGE_TYPE_OPEN_DONE:
		if (current_handler->request() < 0)
			mbim_send_close_msg();
		break;
	case MBIM_MESSAGE_TYPE_COMMAND_DONE:
		return_code = current_handler->response(msg->buffer, le32toh(msg->buffer_length));
		if (return_code < 0)
			no_close = 0;
		mbim_send_close_msg();
		break;
	case MBIM_MESSAGE_TYPE_CLOSE_DONE:
		uloop_end();
		break;
	case MBIM_MESSAGE_TYPE_FUNCTION_ERROR:
		no_close = 0;
		mbim_send_close_msg();
		return_code = -1;
		break;
	}
}

void
mbim_open(const char *path)
{
	mbim_fd.cb = mbim_recv;
	mbim_fd.fd = open(path, O_RDWR);
	if (mbim_fd.fd < 1) {
		perror("open failed: ");
		exit(-1);
	}
	uloop_fd_add(&mbim_fd, ULOOP_READ);
}
