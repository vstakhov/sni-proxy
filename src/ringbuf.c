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
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/uio.h>

#include "ringbuf.h"
#include "util.h"

struct ringbuf*
ringbuf_create(size_t len, const uint8_t *init, size_t initlen)
{
	struct ringbuf *r;
	size_t real_len;

	real_len = initlen > len ? initlen + len : len;
	r = xmalloc(sizeof(*r));
	r->buf = xmalloc(real_len);
	r->end = r->buf + real_len;
	r->read_pos = initlen;
	r->write_pos = 0;
	r->wr_avail = initlen;
	r->rd_avail = real_len - initlen;

	if (init) {
		memcpy(r->buf, init, initlen);
	}

	return r;
}

bool
ringbuf_can_read(struct ringbuf *r)
{
	return r->rd_avail > 0;
}

bool
ringbuf_can_write(struct ringbuf *r)
{
	return r->wr_avail > 0;
}

const struct iovec*
ringbuf_readvec(struct ringbuf *r, int *cnt)
{
	static struct iovec iov[2];
	int p1;

	p1 = MIN(r->rd_avail, (r->end - r->buf) - r->read_pos);
	/* read_pos to end + start to write_pos */
	iov[0].iov_base = r->buf + r->read_pos;
	iov[0].iov_len = p1;

	if (r->rd_avail - p1 > 0) {
		iov[1].iov_base = r->buf;
		iov[1].iov_len = r->rd_avail - p1;
		*cnt = 2;
	}
	else {
		*cnt = 1;
	}

	return iov;
}

const struct iovec*
ringbuf_writevec(struct ringbuf *r, int *cnt)
{
	static struct iovec iov[2];
	int p1;

	/* write_pos to end + start to read_pos */
	p1 = MIN(r->wr_avail, (r->end - r->buf) - r->write_pos);
	iov[0].iov_base = r->buf + r->write_pos;
	iov[0].iov_len = p1;

	if (r->wr_avail - p1 > 0) {
		iov[1].iov_base = r->buf;
		iov[1].iov_len = r->wr_avail - p1;
		*cnt = 2;
	}
	else {
		*cnt = 1;
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
		r->read_pos = len - p1;
	}
	else {
		r->read_pos += len;
	}

	r->wr_avail += len;
	r->rd_avail -= len;

#ifdef RBUF_DEBUG
	fprintf(stderr, "r: %d, ravail: %d, wavail: %d, rpos: %d, wpos: %d\n",
			(int)len, r->rd_avail, r->wr_avail, r->read_pos, r->write_pos);
#endif
}

void
ringbuf_update_write(struct ringbuf *r, ssize_t len)
{
	int p1;

	p1 = (r->end - r->buf) - r->write_pos;
	if (len >= p1) {
		r->write_pos = len - p1;
	}
	else {
		r->write_pos += len;
	}

	r->rd_avail += len;
	r->wr_avail -= len;

#ifdef RBUF_DEBUG
	fprintf(stderr, "w: %d, ravail: %d, wavail: %d, rpos: %d, wpos: %d\n",
			(int)len, r->rd_avail, r->wr_avail, r->read_pos, r->write_pos);
#endif
}

void
ringbuf_destroy(struct ringbuf *r)
{
	if (r) {
		free(r->buf);
		free(r);
	}
}
