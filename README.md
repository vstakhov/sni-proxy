# Transparent TLS SNI proxy

## Overview

TLS server name extension has been defined since [TLS 1.0](https://tools.ietf.org/html/rfc2246).
This extension allows to specify the exact server name to connect. This project implements a transparent
proxy that accepts TLS connection, parses the initial client greeting and proxies the complete SSL
session to the backend corresponding to the server's name (or default backend if no SNI specified).
This proxy **does NOT** require any cryptographic materials: private keys, public keys, certificates.
It does not modify TLS session and does not perform man-in-the middle intrusion. Moreover, it is not
even linked with any cryptographic library.

## Installation

Install `libev` to your system by using either packages or its [home site](http://software.schmorp.de/pkg/libev.html).

Clone sni-proxy from git:

	git clone --recursive https://github.com/vstakhov/sni-proxy

Please note, that `recursive` option is essential, since sni proxy depends on submodules.
If you've forgotten to specify this option when cloning, then type the following:

	git submodule update --init
	
in sni-proxy source directory.

Building is traditional:

	./autogen.sh
	./configure
	make

Since this project is in early alpha stage, I do not provide any packages at this point.

## Running

Write configuration in [ucl](https://github.com/vstakhov/libucl] as following:

```nginx
# Port to listen
port = 443

backends {
	# SNI name
	example.com {
		# Can be name or ip address
		host = real.example.com
		# Default port is 443
		port = 4444
	}
}
```

Afterwards, if `example.com` points to your sni-proxy then connecting to `https://example.com`
using web browser would forward this request to the host named `real.example.com`, port 4444.

## Speed

Sni proxy uses `libev` and non-blocking IO with high performance reactor (e.g. epoll on Linux or kqueue on BSD).
It is written in plain C language with no extra libraries used. Some initial benchmarks has shown that it has
almost the same RPS rate as direct connection to the backend. However, it obviously copies data between
kernel and userspace 2 times. In future, some zero-copy methods could be considered for better performance.

## Disclaimer

This project in alpha stage. It can crash, corrupt data or do other weird things. It is badly
documented and many features are missing. However, it *cannot* make your SSL connections more vulnerable
to attacks and it *cannot* leak your data, heartbleed it or do other stuff. It doesn't work with cryptography
at all.

## SSLv3

No.

## Todo list

1. Load balancing
2. Multiple workers.
3. Automatic buffer sizes and joint limits.
4. Better documentation.
5. Shiny graphs.