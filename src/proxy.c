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
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <assert.h>

#include "ev.h"
#include "ucl.h"
#include "util.h"
#include "ringbuf.h"
#include "sni-private.h"

static void proxy_state_machine(struct ssl_session *s);

static void
timer_cb(EV_P_ ev_timer *w, int revents)
{
	struct ssl_session *ssl = w->data;

	ev_timer_stop(loop, &ssl->tm);
	terminate_session(ssl);
}

static void
close_backend(struct ssl_session *s)
{
	if (s->bk_fd != -1) {
		ev_io_stop(s->loop, &s->bk_io);
		close(s->bk_fd);
		s->bk_fd = -1;

		if (ringbuf_can_write(s->bk2cl)) {
			/* We have some more data in bk2cl buffer */
			shutdown(s->fd, SHUT_RD);
			ev_timer_init(&s->tm, timer_cb, 5.0, 1);
			ev_timer_start(s->loop, &s->tm);
		}
		else {
			/* Nothing to write, close connection completely */
			s->state ++;
			ev_timer_stop(s->loop, &s->tm);
		}
	}
}

static void
close_client(struct ssl_session *s)
{
	if (s->fd != -1) {
		ev_io_stop(s->loop, &s->io);
		close(s->fd);
		s->fd = -1;

		if (ringbuf_can_write(s->cl2bk)) {
			/* We have some more data in cl2bk buffer */
			shutdown(s->bk_fd, SHUT_RD);
			ev_timer_init(&s->tm, timer_cb, 5.0, 1);
			ev_timer_start(s->loop, &s->tm);
		}
		else {
			/* Nothing to write, close connection completely */
			s->state ++;
			ev_timer_stop(s->loop, &s->tm);
		}
	}
}

static void
proxy_cl_bk(EV_P_ ev_io *w, int revents)
{
	ssize_t r;
	const struct iovec *iov;
	struct ssl_session *s = w->data;
	int cnt = 0;

	if (revents & EV_READ) {
		/* Can read from client fd to cl2bk buffer */
		iov = ringbuf_readvec(s->cl2bk, &cnt);

		if (iov[0].iov_len > 0) {
			while ((r = readv(s->fd, iov, cnt)) == -1) {
				if (errno == EINTR) {
					continue;
				}
				else if (errno == EAGAIN) {
					return;
				}
				/* XXX: Handle that */
				s->state ++;
				close_client(s);
				return;
			}

			if (r == 0) {
				/* XXX: handle that */
				s->state ++;
				close_client(s);
				return;
			}

			ringbuf_update_read(s->cl2bk, r);
		}
	}
	if (revents & EV_WRITE) {
		/* Can write to bk fd from cl2bk buffer */
		iov = ringbuf_writevec(s->cl2bk, &cnt);

		if (iov[0].iov_len > 0) {
			while ((r = writev(s->bk_fd, iov, cnt)) == -1) {
				if (errno == EINTR) {
					continue;
				}
				else if (errno == EAGAIN) {
					return;
				}
				/* XXX: Handle that */
				s->state ++;
				close_backend(s);
				return;
			}

			if (r == 0) {
				/* XXX: handle that */
				s->state ++;
				close_backend(s);
				return;
			}

			ringbuf_update_write(s->cl2bk, r);
		}
	}
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
		iov = ringbuf_readvec(s->bk2cl, &cnt);

		if (iov[0].iov_len > 0) {
			while ((r = readv(s->bk_fd, iov, cnt)) == -1) {
				if (errno == EINTR) {
					continue;
				}
				else if (errno == EAGAIN) {
					return;
				}
				s->state ++;
				close_backend(s);
				return;
			}

			if (r == 0) {
				s->state ++;
				close_backend(s);
				return;
			}

			ringbuf_update_read(s->bk2cl, r);
		}
	}
	if (revents & EV_WRITE) {
		/* Can write to client fd from bk2cl buffer */
		iov = ringbuf_writevec(s->bk2cl, &cnt);

		if (iov[0].iov_len > 0) {
			while ((r = writev(s->fd, iov, cnt)) == -1) {
				if (errno == EINTR) {
					continue;
				}
				else if (errno == EAGAIN) {
					return;
				}
				/* XXX: Handle that */
				s->state ++;
				close_client(s);
				return;
			}

			if (r == 0) {
				s->state ++;
				close_client(s);
				return;
			}

			ringbuf_update_write(s->bk2cl, r);
		}
	}
}

static void
proxy_bk_cb(EV_P_ ev_io *w, int revents)
{
	struct ssl_session *s = w->data;

	if (s->bk_fd != -1 && (revents & EV_READ)) {
		/* Backend to client */
		proxy_bk_cl(loop, w, revents);
	}
	if (s->bk_fd != -1 && (revents & EV_WRITE)) {
		/* Buffer to backend */
		proxy_cl_bk(loop, w, revents);
	}
	proxy_state_machine(s);
}

static void
proxy_cl_cb(EV_P_ ev_io *w, int revents)
{
	struct ssl_session *s = w->data;

	if (s->fd != -1 && (revents & EV_READ)) {
		/* Client to backend */
		proxy_cl_bk(loop, w, revents);
	}
	if (s->fd != -1 && (revents & EV_WRITE)) {
		/* Buffer to client */
		proxy_bk_cl(loop, w, revents);
	}
	proxy_state_machine(s);
}

static void
proxy_state_machine(struct ssl_session *s)
{
	int bk_ev = 0, cl_ev = 0;

	if (s->state >= ssl_state_proxy_both_closed) {
		ev_timer_stop(s->loop, &s->tm);
		terminate_session(s);
		return;
	}
	/* Client to backend */
	if (ringbuf_can_read(s->cl2bk)) {
		/* Read data from client to cl2bk buffer */
		cl_ev |= EV_READ;
	}
	if (ringbuf_can_write(s->cl2bk)) {
		/* Write data from client to backend using cl2bk buffer */
		bk_ev |= EV_WRITE;
	}
	/* Backend to client */
	if (ringbuf_can_read(s->bk2cl)) {
		/* Read data from backend to bk2cl buffer */
		bk_ev |= EV_READ;
	}
	if (ringbuf_can_write(s->bk2cl)) {
		/* Write data from backend to client using bk2cl buffer */
		cl_ev |= EV_WRITE;
	}

	if (s->bk_fd != -1) {
		ev_io_stop(s->loop, &s->bk_io);

		if (bk_ev != 0) {
			ev_io_set(&s->bk_io, s->bk_fd, bk_ev);
			ev_io_start(s->loop, &s->bk_io);
		}
	}
	if (s->fd != -1) {
		ev_io_stop(s->loop, &s->io);

		if (cl_ev > 0) {
			ev_io_set(&s->io, s->fd, cl_ev);
			ev_io_start(s->loop, &s->io);
		}
	}
}

void
proxy_create(struct ssl_session *s)
{
	s->state = ssl_state_proxy;

	ev_io_init(&s->bk_io, proxy_bk_cb, s->bk_fd, EV_READ|EV_WRITE);
	ev_io_init(&s->io, proxy_cl_cb, s->fd, EV_READ|EV_WRITE);
	proxy_state_machine(s);
}
