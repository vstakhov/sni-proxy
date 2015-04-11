/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef SRC_RINGBUF_H_
#define SRC_RINGBUF_H_

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/uio.h>

struct ringbuf {
	uint8_t *buf;
	uint8_t *end;
	int read_pos;
	int write_pos;
};

struct ringbuf* ringbuf_create(size_t len, const uint8_t *init, size_t initlen);

bool ringbuf_can_read(struct ringbuf *r);
bool ringbuf_can_write(struct ringbuf *r);

const struct iovec* ringbuf_readvec(struct ringbuf *r, int *cnt);
const struct iovec* ringbuf_writevec(struct ringbuf *r, int *cnt);

void ringbuf_update_read(struct ringbuf *r, ssize_t len);
void ringbuf_update_write(struct ringbuf *r, ssize_t len);

void ringbuf_destroy(struct ringbuf *r);

#endif /* SRC_RINGBUF_H_ */
