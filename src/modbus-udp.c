/*
 * Copyright © 2001-2013 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#if defined(_WIN32)
# define OS_WIN32
/* ws2_32.dll has getaddrinfo and freeaddrinfo on Windows XP and later.
 * minwg32 headers check WINVER before allowing the use of these */
# ifndef WINVER
#   define WINVER 0x0501
# endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <signal.h>
#include <sys/types.h>

#if defined(_WIN32)
/* Already set in modbus-udp.h but it seems order matters in VS2005 */
# include <winsock2.h>
# include <ws2tcpip.h>
# define SHUT_RDWR 2
# define close closesocket
#else
# include <sys/socket.h>
# include <sys/ioctl.h>

#if defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ < 5)
# define OS_BSD
# include <netinet/in_systm.h>
#endif

# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if defined(_AIX) && !defined(MSG_DONTWAIT)
#define MSG_DONTWAIT MSG_NONBLOCK
#endif

#include "modbus-private.h"

#include "modbus-udp.h"
#include "modbus-udp-private.h"

#ifdef OS_WIN32
static int _modbus_udp_init_win32(void)
{
    /* Initialise Windows Socket API */
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup() returned error code %d\n",
                (unsigned int)GetLastError());
        errno = EIO;
        return -1;
    }
    return 0;
}
#endif

static int _modbus_set_slave(modbus_t *ctx, int slave)
{
    /* Broadcast address is 0 (MODBUS_BROADCAST_ADDRESS) */
    if (slave >= 0 && slave <= 247) {
        ctx->slave = slave;
    } else if (slave == MODBUS_UDP_SLAVE) {
        /* The special value MODBUS_UDP_SLAVE (0xFF) can be used in UDP mode to
         * restore the default value. */
        ctx->slave = slave;
    } else {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/* Builds a UDP request header */
static int _modbus_udp_build_request_basis(modbus_t *ctx, int function,
                                           int addr, int nb,
                                           uint8_t *req)
{
    modbus_udp_t *ctx_udp = ctx->backend_data;

    /* Increase transaction ID */
    if (ctx_udp->t_id < UINT16_MAX)
        ctx_udp->t_id++;
    else
        ctx_udp->t_id = 0;
    req[0] = ctx_udp->t_id >> 8;
    req[1] = ctx_udp->t_id & 0x00ff;

    /* Protocol Modbus */
    req[2] = 0;
    req[3] = 0;

    /* Length will be defined later by set_req_length_udp at offsets 4
       and 5 */

    req[6] = ctx->slave;
    req[7] = function;
    req[8] = addr >> 8;
    req[9] = addr & 0x00ff;
    req[10] = nb >> 8;
    req[11] = nb & 0x00ff;

    return _MODBUS_UDP_PRESET_REQ_LENGTH;
}

/* Builds a UDP response header */
static int _modbus_udp_build_response_basis(sft_t *sft, uint8_t *rsp)
{
    /* Extract from MODBUS Messaging on UDP/IP Implementation
       Guide V1.0b (page 23/46):
       The transaction identifier is used to associate the future
       response with the request. */
    rsp[0] = sft->t_id >> 8;
    rsp[1] = sft->t_id & 0x00ff;

    /* Protocol Modbus */
    rsp[2] = 0;
    rsp[3] = 0;

    /* Length will be set later by send_msg (4 and 5) */

    /* The slave ID is copied from the indication */
    rsp[6] = sft->slave;
    rsp[7] = sft->function;

    return _MODBUS_UDP_PRESET_RSP_LENGTH;
}


static int _modbus_udp_prepare_response_tid(const uint8_t *req, int *req_length)
{
    return (req[0] << 8) + req[1];
}

static int _modbus_udp_send_msg_pre(uint8_t *req, int req_length)
{
    /* Substract the header length to the message length */
    int mbap_length = req_length - 6;

    req[4] = mbap_length >> 8;
    req[5] = mbap_length & 0x00FF;

    return req_length;
}

static ssize_t _modbus_udp_send(modbus_t *ctx, const uint8_t *req, int req_length)
{
    /* MSG_NOSIGNAL
       Requests not to send SIGPIPE on errors on stream oriented
       sockets when the other end breaks the connection.  The EPIPE
       error is still returned. */
    return send(ctx->s, (const char *)req, req_length, MSG_NOSIGNAL);
}

static int _modbus_udp_receive(modbus_t *ctx, uint8_t *req) {
    return _modbus_receive_msg(ctx, req, MSG_INDICATION);
}

static ssize_t _modbus_udp_recv(modbus_t *ctx, uint8_t *rsp, int rsp_length) {
	// Do some input buffer management.
	modbus_udp_t *ctx_udp = ctx->backend_data;
	if( ctx_udp->_u ) {
		int len = ctx_udp->_u > rsp_length ? rsp_length : ctx_udp->_u;
		memcpy(rsp, ctx_udp->buffer, (size_t) len);
		ctx_udp->_u -= len;
        memmove(ctx_udp->buffer, ctx_udp->buffer + len, (size_t)ctx_udp->_u);
		return len;
	} else {
		if( rsp_length > MODBUS_UDP_MAX_ADU_LENGTH )
			rsp_length = MODBUS_UDP_MAX_ADU_LENGTH;

		int b;
		ssize_t rc = ioctl(ctx->s,FIONREAD, &b);
		if( !rc ) {
			rc = recv(ctx->s, (char *)ctx_udp->buffer, (size_t)b, 0);
			if(rc > 0 ) {
				ssize_t len = rc > rsp_length ? rsp_length: rc;
				memcpy(rsp, ctx_udp->buffer, (size_t) len);
				ctx_udp->_u = (int)(rc - len);
				memmove(ctx_udp->buffer,ctx_udp->buffer+len,(size_t)ctx_udp->_u);
				return len;
			}
		}
	}
	return -1;
}

static int _modbus_udp_check_integrity(modbus_t *ctx, uint8_t *msg, const int msg_length)
{
    return msg_length;
}

static int _modbus_udp_pre_check_confirmation(modbus_t *ctx, const uint8_t *req,
                                              const uint8_t *rsp, int rsp_length)
{
    /* Check transaction ID */
    if (req[0] != rsp[0] || req[1] != rsp[1]) {
        if (ctx->debug) {
            fprintf(stderr, "Invalid transaction ID received 0x%X (not 0x%X)\n",
                    (rsp[0] << 8) + rsp[1], (req[0] << 8) + req[1]);
        }
        errno = EMBBADDATA;
        return -1;
    }

    /* Check protocol ID */
    if (rsp[2] != 0x0 && rsp[3] != 0x0) {
        if (ctx->debug) {
            fprintf(stderr, "Invalid protocol ID received 0x%X (not 0x0)\n",
                    (rsp[2] << 8) + rsp[3]);
        }
        errno = EMBBADDATA;
        return -1;
    }

    return 0;
}

static int _modbus_udp_set_ipv4_options(int s)
{
    int rc;
    int option;
#if 0

    /* Set the UDP no delay flag */
    /* SOL_UDP = IPPROTO_UDP */
    option = 1;
    rc = setsockopt(s, IPPROTO_UDP, TCP_NODELAY,
                    (const void *)&option, sizeof(int));
    if (rc == -1) {
        return -1;
    }

#endif

    /* If the OS does not offer SOCK_NONBLOCK, fall back to setting FIONBIO to
     * make sockets non-blocking */
    /* Do not care about the return value, this is optional */
#if !defined(SOCK_NONBLOCK) && defined(FIONBIO)
#ifdef OS_WIN32
    {
        /* Setting FIONBIO expects an unsigned long according to MSDN */
        u_long loption = 1;
        ioctlsocket(s, FIONBIO, &loption);
    }
#else
    option = 1;
    ioctl(s, FIONBIO, &option);
#endif
#endif

#ifndef OS_WIN32
    /**
     * Cygwin defines IPTOS_LOWDELAY but can't handle that flag so it's
     * necessary to workaround that problem.
     **/
    /* Set the IP low delay option */
    option = IPTOS_LOWDELAY;
    rc = setsockopt(s, IPPROTO_IP, IP_TOS,
                    (const void *)&option, sizeof(int));
    if (rc == -1) {
        return -1;
    }
#endif

    return 0;
}

static int _connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
                    const struct timeval *ro_tv)
{
    int rc = connect(sockfd, addr, addrlen);

#ifdef OS_WIN32
    int wsaError = 0;
    if (rc == -1) {
        wsaError = WSAGetLastError();
    }

    if (wsaError == WSAEWOULDBLOCK || wsaError == WSAEINPROGRESS) {
#else
    if (rc == -1 && errno == EINPROGRESS) {
#endif
        fd_set wset;
        int optval;
        socklen_t optlen = sizeof(optval);
        struct timeval tv = *ro_tv;

        /* Wait to be available in writing */
        FD_ZERO(&wset);
        FD_SET(sockfd, &wset);
        rc = select(sockfd + 1, NULL, &wset, NULL, &tv);
        if (rc <= 0) {
            /* Timeout or fail */
            return -1;
        }

        /* The connection is established if SO_ERROR and optval are set to 0 */
        rc = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)&optval, &optlen);
        if (rc == 0 && optval == 0) {
            return 0;
        } else {
            errno = ECONNREFUSED;
            return -1;
        }
    }
    return rc;
}

/* Establishes a modbus UDP connection with a Modbus server. */
static int _modbus_udp_connect(modbus_t *ctx)
{
    int rc;
    /* Specialized version of sockaddr for Internet socket address (same size) */
    struct sockaddr_in addr;
    modbus_udp_t *ctx_udp = ctx->backend_data;
    int flags = SOCK_DGRAM;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

#ifdef SOCK_CLOEXEC
    flags |= SOCK_CLOEXEC;
#endif

#ifdef SOCK_NONBLOCK
    flags |= SOCK_NONBLOCK;
#endif

    ctx->s = socket(PF_INET, flags, 0);
    if (ctx->s == -1) {
        return -1;
    }

    rc = _modbus_udp_set_ipv4_options(ctx->s);
    if (rc == -1) {
        close(ctx->s);
        ctx->s = -1;
        return -1;
    }

    if (ctx->debug) {
        printf("Connecting to %s:%d\n", ctx_udp->ip, ctx_udp->port);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx_udp->port);
    addr.sin_addr.s_addr = inet_addr(ctx_udp->ip);
    rc = _connect(ctx->s, (struct sockaddr *)&addr, sizeof(addr), &ctx->response_timeout);
    if (rc == -1) {
        close(ctx->s);
        ctx->s = -1;
        return -1;
    }

    return 0;
}

static unsigned int _modbus_udp_is_connected(modbus_t *ctx)
{
    return ctx->s >= 0;
}

/* Closes the network connection and socket in UDP mode */
static void _modbus_udp_close(modbus_t *ctx)
{
    if (ctx->s != -1) {
        shutdown(ctx->s, SHUT_RDWR);
        close(ctx->s);
        ctx->s = -1;
    }
}

static int _modbus_udp_flush(modbus_t *ctx)
{
    int rc;
    int rc_sum = 0;

    modbus_udp_t *ctx_udp = ctx->backend_data;
	ctx_udp->_u = 0;

    do {
        /* Extract the garbage from the socket */
        char devnull[MODBUS_UDP_MAX_ADU_LENGTH];
#ifndef OS_WIN32
        rc = recv(ctx->s, devnull, MODBUS_UDP_MAX_ADU_LENGTH, MSG_DONTWAIT);
#else
        /* On Win32, it's a bit more complicated to not wait */
        fd_set rset;
        struct timeval tv;

        tv.tv_sec = 0;
        tv.tv_usec = 0;
        FD_ZERO(&rset);
        FD_SET(ctx->s, &rset);
        rc = select(ctx->s+1, &rset, NULL, NULL, &tv);
        if (rc == -1) {
            return -1;
        }

        if (rc == 1) {
            /* There is data to flush */
            rc = recv(ctx->s, devnull, MODBUS_UDP_MAX_ADU_LENGTH, 0);
        }
#endif
        if (rc > 0) {
            rc_sum += rc;
        }
    } while (rc == MODBUS_UDP_MAX_ADU_LENGTH);

    return rc_sum;
}

/* Listens for any request from one or many modbus masters in UDP */
int modbus_udp_listen(modbus_t *ctx, int nb_connection)
{
    int new_s;
    int enable;
    int flags;
    struct sockaddr_in addr;
    modbus_udp_t *ctx_udp;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    ctx_udp = ctx->backend_data;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

    flags = SOCK_STREAM;

#ifdef SOCK_CLOEXEC
    flags |= SOCK_CLOEXEC;
#endif

    new_s = socket(PF_INET, flags, IPPROTO_UDP);
    if (new_s == -1) {
        return -1;
    }

    enable = 1;
    if (setsockopt(new_s, SOL_SOCKET, SO_REUSEADDR,
                   (char *)&enable, sizeof(enable)) == -1) {
        close(new_s);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    /* If the modbus port is < to 1024, we need the setuid root. */
    addr.sin_port = htons(ctx_udp->port);
    if (ctx_udp->ip[0] == '0') {
        /* Listen any addresses */
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        /* Listen only specified IP address */
        addr.sin_addr.s_addr = inet_addr(ctx_udp->ip);
    }
    if (bind(new_s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(new_s);
        return -1;
    }

    if (listen(new_s, nb_connection) == -1) {
        close(new_s);
        return -1;
    }

    return new_s;
}

int modbus_udp_accept(modbus_t *ctx, int *s)
{
    struct sockaddr_in addr;
    socklen_t addrlen;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    addrlen = sizeof(addr);
#ifdef HAVE_ACCEPT4
    /* Inherit socket flags and use accept4 call */
    ctx->s = accept4(*s, (struct sockaddr *)&addr, &addrlen, SOCK_CLOEXEC);
#else
    ctx->s = accept(*s, (struct sockaddr *)&addr, &addrlen);
#endif

    if (ctx->s == -1) {
        return -1;
    }

    if (ctx->debug) {
        printf("The client connection from %s is accepted\n",
               inet_ntoa(addr.sin_addr));
    }

    return ctx->s;
}

int modbus_udp_pi_accept(modbus_t *ctx, int *s)
{
    struct sockaddr_storage addr;
    socklen_t addrlen;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    addrlen = sizeof(addr);
#ifdef HAVE_ACCEPT4
    /* Inherit socket flags and use accept4 call */
    ctx->s = accept4(*s, (struct sockaddr *)&addr, &addrlen, SOCK_CLOEXEC);
#else
    ctx->s = accept(*s, (struct sockaddr *)&addr, &addrlen);
#endif

    if (ctx->s == -1) {
        return -1;
    }

    if (ctx->debug) {
        printf("The client connection is accepted.\n");
    }

    return ctx->s;
}

static int _modbus_udp_select(modbus_t *ctx, fd_set *rset, struct timeval *tv, int length_to_read)
{
    int s_rc;
    modbus_udp_t *ctx_udp = ctx->backend_data;

	// Always return true if data exists in read buffer.
	if( ctx_udp->_u )
		return 1;

    while ((s_rc = select(ctx->s+1, rset, NULL, NULL, tv)) == -1) {
        if (errno == EINTR) {
            if (ctx->debug) {
                fprintf(stderr, "A non blocked signal was caught\n");
            }
            /* Necessary after an error */
            FD_ZERO(rset);
            FD_SET(ctx->s, rset);
        } else {
            return -1;
        }
    }

    if (s_rc == 0) {
        errno = ETIMEDOUT;
        return -1;
    }

    return s_rc;
}

static void _modbus_udp_free(modbus_t *ctx) {
    free(ctx->backend_data);
    free(ctx);
}

const modbus_backend_t _modbus_udp_backend = {
    _MODBUS_BACKEND_TYPE_UDP,
    _MODBUS_UDP_HEADER_LENGTH,
    _MODBUS_UDP_CHECKSUM_LENGTH,
    MODBUS_UDP_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_udp_build_request_basis,
    _modbus_udp_build_response_basis,
    _modbus_udp_prepare_response_tid,
    _modbus_udp_send_msg_pre,
    _modbus_udp_send,
    _modbus_udp_receive,
    _modbus_udp_recv,
    _modbus_udp_check_integrity,
    _modbus_udp_pre_check_confirmation,
    _modbus_udp_connect,
    _modbus_udp_is_connected,
    _modbus_udp_close,
    _modbus_udp_flush,
    _modbus_udp_select,
    _modbus_udp_free
};

modbus_t* modbus_new_udp(const char *ip, int port)
{
    modbus_t *ctx;
    modbus_udp_t *ctx_udp;
    size_t dest_size;
    size_t ret_size;

#if defined(OS_BSD)
    /* MSG_NOSIGNAL is unsupported on *BSD so we install an ignore
       handler for SIGPIPE. */
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        /* The debug flag can't be set here... */
        fprintf(stderr, "Could not install SIGPIPE handler.\n");
        return NULL;
    }
#endif

    ctx = (modbus_t *)malloc(sizeof(modbus_t));
    if (ctx == NULL) {
        return NULL;
    }
    _modbus_init_common(ctx);

    /* Could be changed after to reach a remote serial Modbus device */
    ctx->slave = MODBUS_UDP_SLAVE;

    ctx->backend = &_modbus_udp_backend;

    ctx->backend_data = (modbus_udp_t *)malloc(sizeof(modbus_udp_t));
    if (ctx->backend_data == NULL) {
        modbus_free(ctx);
        errno = ENOMEM;
        return NULL;
    }
    ctx_udp = (modbus_udp_t *)ctx->backend_data;

    if (ip != NULL) {
        dest_size = sizeof(char) * 16;
        ret_size = strlcpy(ctx_udp->ip, ip, dest_size);
        if (ret_size == 0) {
            fprintf(stderr, "The IP string is empty\n");
            modbus_free(ctx);
            errno = EINVAL;
            return NULL;
        }

        if (ret_size >= dest_size) {
            fprintf(stderr, "The IP string has been truncated\n");
            modbus_free(ctx);
            errno = EINVAL;
            return NULL;
        }
    } else {
        ctx_udp->ip[0] = '0';
    }
    ctx_udp->port = port;
    ctx_udp->t_id = ctx_udp->_u = 0;

    return ctx;
}
