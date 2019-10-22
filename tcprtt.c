/*-
 * Copyright (C) 2016 Olivier Poitrey <rs@netflix.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/arb.h>
#include <sys/errno.h>
#include <sys/qmath.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/stats.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

static int
get_rtt(int domain, const struct sockaddr *addr, socklen_t addrlen);

static int
usage(void);

/*
 * The tcprtt utility reliably measures the TCP handshake round trip time
 * using the stats(9) statistics framework.
 */
int
main(int argc, char *argv[])
{
	struct addrinfo hints, *res, *res0;
	int c, family, first, lasterr, rtt;
	char host[NI_MAXHOST], serv[NI_MAXSERV];

        /* Stop at first value for each given address family */
	first = 0;

        while ((c = getopt (argc, argv, "f")) != -1) {
	    if (c == 'f')
	        first = 1;
	    else
	        return usage();
	}

	/* Parse options: <host> <port> */
	if (argc != optind + 2) {
	    return usage();
	}
	strncpy(host, argv[optind], sizeof(host));
	strncpy(serv, argv[optind+1], sizeof(serv));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(host, serv, &hints, &res0)) {
	    err(EX_OSERR, "getaddrinfo");
        }
	lasterr = 0;
	for (res = res0; res; res = res->ai_next) {
	    family = 4;
	    if (res->ai_family == AF_INET6) {
	        family = 6;
	    }
	    /* if -f option is provided, check if this address family already got
               a result */
	    if (first > 0 && ((first >> family) & 1) == 1) {
	        continue;
	    }
	    rtt = get_rtt(res->ai_family, res->ai_addr, res->ai_addrlen);
	    if (rtt < 0) {
	        lasterr = rtt;
	    }
	    /* store the fact we got a response for this address family */
	    if (first > 0) {
	        first |= 1 << family;
	    }
	    getnameinfo(res->ai_addr, res->ai_addrlen,
	        host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST);
	    printf("%d %s %d\n", family, host, rtt);
	}
	freeaddrinfo(res0);

	return(-lasterr);
}

int
usage()
{
	printf("Syntax: tcprtt [-f] <host> <port>\n");
	return(EX_USAGE);
}

int
get_rtt(int domain, const struct sockaddr *addr, socklen_t addrlen)
{
	struct statsblob *sb;
	socklen_t sockoptlen;
	uint32_t rtt;
	int enable_stats, error, ret, s;

        /* Create a TCP socket */
        s = socket(domain, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0) {
	    return(-errno);
        }

	/* Enable stats gathering on the socket */
	enable_stats = 1;
	if (setsockopt(s, IPPROTO_TCP, TCP_STATS, &enable_stats, sizeof(enable_stats)) != 0) {
	    close(s);
	    return(-errno);
	}

	/* Connect to specified addr */
	if (connect(s, addr, addrlen) < 0) {
	    close(s);
	    return(-errno);
	}

	/* Use Lawrence's kernel RTT stats feature to get precise measurement of the RTT */
	sockoptlen = 2048;
	sb = (struct statsblob *)malloc(sockoptlen);
	if (sb == NULL) {
	    close(s);
	    free(sb);
	    return(-errno);
	}
	if ((ret = getsockopt(s, IPPROTO_TCP, TCP_STATS, sb, &sockoptlen))) {
	    if (errno == EOVERFLOW && sb->cursz > sockoptlen) {
	        /* Retry with a larger size. */
	        sockoptlen = sb->cursz;
	        sb = realloc(sb, sockoptlen);
	        if (sb == NULL)
	            errno = ENOMEM;
	        else
	            ret = getsockopt(s, IPPROTO_TCP, TCP_STATS, sb, &sockoptlen);
	    }
	    if (ret != 0) {
	        close(s);
	        free(sb);
	        return (-errno);
	    }
	}

	error = stats_voistat_fetch_u32(sb, VOI_TCP_RTT, VS_STYPE_MAX, &rtt);
	close(s);
	free(sb);
	if (error != 0)
	    return (-error);

	return (rtt);
}
