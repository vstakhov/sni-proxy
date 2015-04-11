/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
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
#ifndef SNI_PRIVATE_H_
#define SNI_PRIVATE_H_

#include "ev.h"
#include "ucl.h"
#include "ringbuf.h"

struct ssl_session {
	const ucl_object_t *backends;
	ev_io io;
	ev_io bk_io;
	struct ev_loop *loop;
	char *hostname;
	struct ringbuf *cl2bk;
	struct ringbuf *bk2cl;
	unsigned hostlen;
	enum {
		ssl_state_init = 0,
		ssl_state_alert,
		ssl_state_alert_sent,
		ssl_state_backend_selected,
		ssl_state_backend_ready,
		ssl_state_backend_greeting
	} state;
	int fd;
	int bk_fd;
	uint8_t ssl_version[2];
	uint8_t *saved_buf;
	int buflen;
};

void send_alert(struct ssl_session *ssl);
void terminate_session(struct ssl_session *ssl);

#endif /* SNI_PRIVATE_H_ */
