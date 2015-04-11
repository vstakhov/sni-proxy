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

#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/uio.h>

#include "ringbuf.h"
#include "util.h"

struct ringbuf*
ringbuf_create(size_t len, uint8_t *init, size_t initlen)
{
	struct ringbuf *r;
	size_t real_len;

	real_len = initlen > len ? initlen + len : len;
	r = xmalloc(sizeof(*r));
	r->buf = xmalloc(real_len);
	r->end = r->buf + real_len;
	r->read_pos = initlen;
	r->write_pos = 0;

	return r;
}

bool
ringbuf_can_read(struct ringbuf *r)
{
	int avail = 0;

	if (r->read_pos >= r->write_pos) {
		/* read_pos to end + start to write_pos */
		avail = (r->end - r->buf) - r->read_pos + r->write_pos;
	}
	else {
		/* read_pos to write_pos */
		avail = r->write_pos - r->read_pos;
	}

	return avail > 0;
}

bool
ringbuf_can_write(struct ringbuf *r)
{
	int avail = 0;

	if (r->read_pos >= r->write_pos) {
		/* read_pos to write_pos */
		avail = r->read_pos - r->write_pos;
	}
	else {
		/* write_pos to end + start to read_pos */
		avail = (r->end - r->buf) - r->write_pos + r->read_pos;
	}

	return avail > 0;
}

const struct iovec*
ringbuf_readvec(struct ringbuf *r, int *cnt)
{
	static struct iovec iov[2];

	if (r->read_pos >= r->write_pos) {
		/* read_pos to end + start to write_pos */
		iov[0].iov_base = r->buf + r->read_pos;
		iov[0].iov_len = (r->end - r->buf) - r->read_pos;
		iov[1].iov_base = r->buf;
		iov[1].iov_len = r->write_pos;

		if (iov[1].iov_len > 0) {
			*cnt = 2;
		}
		else {
			*cnt = 1;
		}
	}
	else {
		/* read_pos to write_pos */
		iov[0].iov_base = r->buf + r->read_pos;
		iov[0].iov_len = r->write_pos - r->read_pos;
		*cnt = 1;
	}

	return iov;
}

const struct iovec*
ringbuf_writevec(struct ringbuf *r, int *cnt)
{
	static struct iovec iov[2];

	if (r->read_pos >= r->write_pos) {
		/* read_pos to write_pos */
		iov[0].iov_base = r->buf + r->write_pos;
		iov[0].iov_len = r->read_pos - r->write_pos;
		*cnt = 1;
	}
	else {
		/* write_pos to end + start to read_pos */
		iov[0].iov_base = r->buf + r->write_pos;
		iov[0].iov_len = (r->end - r->buf) - r->write_pos;
		iov[1].iov_base = r->buf;
		iov[1].iov_len = r->read_pos;

		if (iov[1].iov_len > 0) {
			*cnt = 2;
		}
		else {
			*cnt = 1;
		}
	}

	return iov;
}

void
ringbuf_update_read(struct ringbuf *r, ssize_t len)
{
	int p1;

	/* read_pos to end + start to write_pos */
	p1 = (r->end - r->buf) - r->read_pos;
	if (len >= p1) {
		len -= p1;
		r->read_pos = len;
	}
	else {
		r->read_pos += len;
	}
}

void
ringbuf_update_write(struct ringbuf *r, ssize_t len)
{
	int p1;

	p1 = (r->end - r->buf) - r->write_pos;
	if (len >= p1) {
		len -= p1;
		r->write_pos = len;
	}
	else {
		r->write_pos += len;
	}
}

void
ringbuf_destroy(struct ringbuf *r)
{
	if (r) {
		free(r->buf);
		free(r);
	}
}
