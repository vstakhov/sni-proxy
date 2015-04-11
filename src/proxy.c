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
#include <errno.h>

#include "ev.h"
#include "ucl.h"
#include "util.h"
#include "ringbuf.h"
#include "sni-private.h"

static void proxy_state_machine(struct ssl_session *s);

static void
proxy_cl_bk(EV_P_ ev_io *w, int revents)
{
	ssize_t r;
	const struct iovec *iov;
	struct ssl_session *s = w->data;
	int cnt = 0;

	if (revents & EV_READ) {
		/* Can read from client fd to cl2bk buffer */
		ev_io_stop(s->loop, &s->io);
		iov = ringbuf_readvec(s->cl2bk, &cnt);

		while ((r = readv(s->fd, iov, cnt)) == -1) {
			if (errno == EINTR) {
				continue;
			}
			/* XXX: Handle that */
			break;
		}

		if (r == 0) {
			/* XXX: handle that */
		}

		ringbuf_update_read(s->cl2bk, r);
	}
	if (revents & EV_WRITE) {
		/* Can write to bk fd from cl2bk buffer */
		ev_io_stop(s->loop, &s->bk_io);
		iov = ringbuf_writevec(s->cl2bk, &cnt);

		while ((r = writev(s->bk_fd, iov, cnt)) == -1) {
			if (errno == EINTR) {
				continue;
			}
			/* XXX: Handle that */
			break;
		}

		if (r == 0) {
			/* XXX: handle that */
		}

		ringbuf_update_write(s->cl2bk, r);
	}

	proxy_state_machine(s);
}

static void
proxy_bk_cl(EV_P_ ev_io *w, int revents)
{
	ssize_t r;
	const struct iovec *iov;
	struct ssl_session *s = w->data;
	int cnt = 0;

	if (revents & EV_READ) {
		/* Can read from backend fd to bk2cl buffer */
		ev_io_stop(s->loop, &s->bk_io);
		iov = ringbuf_readvec(s->bk2cl, &cnt);

		while ((r = readv(s->bk_fd, iov, cnt)) == -1) {
			if (errno == EINTR) {
				continue;
			}
			/* XXX: Handle that */
			break;
		}

		if (r == 0) {
			/* XXX: handle that */
		}

		ringbuf_update_read(s->bk2cl, r);
	}
	if (revents & EV_WRITE) {
		/* Can write to client fd from bk2cl buffer */
		ev_io_stop(s->loop, &s->io);
		iov = ringbuf_writevec(s->bk2cl, &cnt);

		while ((r = writev(s->fd, iov, cnt)) == -1) {
			if (errno == EINTR) {
				continue;
			}
			/* XXX: Handle that */
			break;
		}

		if (r == 0) {
			/* XXX: handle that */
		}

		ringbuf_update_write(s->bk2cl, r);
	}

	proxy_state_machine(s);
}

static void
proxy_state_machine(struct ssl_session *s)
{
	/* Client to backend */
	if (ringbuf_can_read(s->cl2bk)) {
		/* Read data from client to cl2bk buffer */
		ev_io_init(&s->io, proxy_cl_bk, s->fd, EV_READ);
		ev_io_start(s->loop, &s->io);
	}
	if (ringbuf_can_write(s->cl2bk)) {
		/* Write data from client to backend using cl2bk buffer */
		ev_io_init(&s->bk_io, proxy_cl_bk, s->bk_fd, EV_WRITE);
		ev_io_start(s->loop, &s->bk_io);
	}
	/* Backend to client */
	if (ringbuf_can_read(s->cl2bk)) {
		/* Read data from client to cl2bk buffer */
		ev_io_init(&s->bk_io, proxy_bk_cl, s->bk_fd, EV_READ);
		ev_io_start(s->loop, &s->bk_io);
	}
	if (ringbuf_can_write(s->cl2bk)) {
		/* Write data from client to backend using cl2bk buffer */
		ev_io_init(&s->io, proxy_bk_cl, s->fd, EV_WRITE);
		ev_io_start(s->loop, &s->io);
	}
}

void
proxy_create(struct ssl_session *s)
{
	s->state = ssl_state_proxy;

	proxy_state_machine(s);
}
