/******************************************************************************
 *
 * Copyright (c) 2016
 * All rights reserved.
 *
 * FILE NAME  :		bufferevent_cyassl.c
 * VERSION    :		1.0
 * DESCRIPTION:   	management of cyassl connection, using evbuffer and event
 *					provided by libevent
 *
 * AUTHOR     :		Xiao Chenglin
 * 					
 * CREATE DATE:		04/07/2015
 *
 * HISTORY    :
 * 01	04/07/2016	Xiao Chenglin create
 *
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <resolv.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "evaddrinfo.h"
#include "bufferevent_cyassl.h"


#define UTIL_ERR_CONNECT_RETRIABLE(e)					\
	((e) == EINTR ||						\
	    (e) == EINPROGRESS)

#define UTIL_ERR_CONNECT_REFUSED(e)					\
	((e) == ECONNREFUSED)


enum {
	BEV_CYASSL_DISCONNECTED = 0,
    BEV_CYASSL_TCP_CONNECTING,
    BEV_CYASSL_TCP_CONNECTED,
    BEV_CYASSL_CONNECTING,
	BEV_CYASSL_CONNECTED
};

enum {
	/* For reading, used when the read buffer has been filled up to 
	   its watermark value. */
	BEV_CYASSL_SUSPEND_WM = 0x01,

	/* For writing, used when the write buffer has been filled up to
	   its watermark value. */
	BEV_CYASSL_SUSPEND_LOOKUP = 0x02
};

struct bufev_cyassl_private {
	struct event_watermark wm_read;
	struct event_watermark wm_write;
	
	/* If set, read is suspended util one or more conditions are over.
	 * The actual value here is a bitfield of thoese conditions, see 
	 * the definition of bev_ssl_SUSPEND_* flags above.
	*/
	unsigned short read_suspend;
	
	/* If set, writing is suspended util one or more conditions are over.
	 * The actual value here is a bitfield of thoese conditions, see 
	 * the definition of bev_ssl_SUSPEND_* flags above.
	*/
	unsigned short write_suspend;	

};

struct bufferevent_cyassl_s {
	struct event_base* base;

	CYASSL* ssl;
	CYASSL_CTX* ctx;
	evutil_socket_t fd;

	int state;
	int port;
	char host[256];

	unsigned int connection_refused;

	short enabled;				// EV_READ/EV_WRITE/EV_PERSIST
	struct evbuffer* input;		// data input buffer
	struct evbuffer* output;	// data output buffer
	
	struct event ev_read;		// read event
	struct event ev_write;		// write event
	
	struct timeval timeout_read;	// read timeout event
	struct timeval timeout_write;	// write timeout event

	struct bufev_cyassl_private cyassl_private;

	bufferevent_cyassl_data_cb read_cb;	    // users' read callback
	bufferevent_cyassl_data_cb write_cb;	// users' write callback
	bufferevent_cyassl_event_cb event_cb;	// users' event callback

	evaddrinfo_t* evaddrinfo;
	void* arg;
};

static int be_cyassl_set_connected_cb(bufferevent_cyassl_t *bev_ssl, evutil_socket_t fd);
static int be_cyassl_set_handshake_cb(bufferevent_cyassl_t *bev_ssl, evutil_socket_t fd);

// read data from cyassl
static int be_cyassl_read(bufferevent_cyassl_t* bev_ssl, void *data, size_t size)
{
	int res = 0;
	int cnt = 0;

	if (!bev_ssl || !data) {
		return -1;
	}

    if (size == 0) {
        return res;
    }

	while ( (size-res) > 0 && (cnt = CyaSSL_read(bev_ssl->ssl, data+res, size-res)) > 0 ) {
		res += cnt;
	}

	return res;
}

// write data to cyassl
static int be_cyassl_write(bufferevent_cyassl_t* bev_ssl, const void *data, size_t size)
{
	int res = 0;
	int cnt = 0;

	if (!bev_ssl || !data ) {
		return -1;
	}

    if (size == 0) {
        return res;
    }

	while ( (size-res) > 0 && (cnt = CyaSSL_write(bev_ssl->ssl, data+res, size-res)) > 0 ) {
		res += cnt;
	}

	return res;
}

// read data from cyassl
static int be_cyassl_read_buffer(bufferevent_cyassl_t* bev_ssl, struct evbuffer* evbuf)
{
	int res = 0;
	int cnt = 0;
	char buf[1024] = {0};
	
	if (!bev_ssl || !evbuf) {
		return -1;
	}

	while ( (cnt = be_cyassl_read(bev_ssl, buf, sizeof(buf)-1)) > 0 ) {
		if ( evbuffer_add(evbuf, buf, cnt) < 0 ) {
			return -1;
		}
		res += cnt;
        memset(buf, 0, sizeof(buf));
	}

	return res;
}

// write data to cyassl
static int be_cyassl_write_buffer(bufferevent_cyassl_t *bev_ssl, struct evbuffer *evbuf)
{
	int res = 0;
	int cnt = 0;
	int buf_len = 0;
	char buf[1024] = {0};

	if (!bev_ssl || !evbuf) {
		return -1;
	}

	buf_len = evbuffer_get_length(evbuf);
	if (buf_len == 0) {
		return res; //buffer is empty
	}

	while (buf_len > 0) {
		memset(buf, 0, sizeof(buf));
		cnt = evbuffer_copyout(evbuf, buf, sizeof(buf)-1);
		
		if (cnt < 0) {
			return -1;
		}

		cnt = be_cyassl_write(bev_ssl, buf, cnt);
		if (cnt <= 0) {
			break;
		}

		evbuffer_drain(evbuf, cnt);
		buf_len -= cnt;
		res += cnt;
	}

	return res;
}

static void be_cyassl_run_readcb(bufferevent_cyassl_t *bev_ssl)
{
	if (bev_ssl && bev_ssl->read_cb) {
		bev_ssl->read_cb(bev_ssl, bev_ssl->arg);
	}
}

static void be_cyassl_run_writecb(bufferevent_cyassl_t *bev_ssl)
{
	if (bev_ssl && bev_ssl->write_cb) {
		bev_ssl->write_cb(bev_ssl, bev_ssl->arg);
	}
}

static void be_cyassl_run_eventcb(bufferevent_cyassl_t *bev_ssl, short what)
{
	if (bev_ssl && bev_ssl->event_cb) {
		bev_ssl->event_cb(bev_ssl, what, bev_ssl->arg);
	}
}

static int be_cyassl_add_event(struct event *ev, const struct timeval *tv)
{
	if (tv && tv->tv_sec == 0 && tv->tv_usec == 0) {
		return event_add(ev, NULL);
	} else {
		return event_add(ev, tv);
	}
}

static int be_cyassl_enable(bufferevent_cyassl_t *bev_ssl, short events)
{
	int r1 = 0, r2 = 0;
	
	if (events & EV_READ) {
		r1 = be_cyassl_add_event(&bev_ssl->ev_read, &bev_ssl->timeout_read);
	}
	if (events & EV_WRITE) {
		r2 = be_cyassl_add_event(&bev_ssl->ev_write, &bev_ssl->timeout_write);
	}
	
	return (r1 < 0 || r2 < 0) ? -1 : 0;
}

static int be_cyassl_disable(bufferevent_cyassl_t *bev_ssl, short events)
{	
	if (events & EV_READ) {
		if (event_del(&bev_ssl->ev_read) == -1) {
			return -1;
		}
	}

	/* Don't actually disable the write when we are trying to connect. */
	if ((events & EV_WRITE) && (BEV_CYASSL_TCP_CONNECTING != bev_ssl->state) 
		&& (BEV_CYASSL_CONNECTING != bev_ssl->state)) {
		if (event_del(&bev_ssl->ev_write) == -1) {
			return -1;
		}
	}

	return 0;
}

static void be_cyassl_suspend_read(bufferevent_cyassl_t *bev_ssl, unsigned short flag)
{
	if (bev_ssl) {
		if (!bev_ssl->cyassl_private.read_suspend) {
			be_cyassl_disable(bev_ssl, EV_READ);
		}
		bev_ssl->cyassl_private.read_suspend |= flag;
	}
}

static void be_cyassl_unsuspend_read(bufferevent_cyassl_t *bev_ssl, unsigned short flag)
{
	if (bev_ssl) {
		bev_ssl->cyassl_private.read_suspend &= ~flag;
		if (!bev_ssl->cyassl_private.read_suspend && (bev_ssl->enabled & EV_READ)) {
			be_cyassl_enable(bev_ssl, EV_READ);
		}
	}
}

static void be_cyassl_suspend_write(bufferevent_cyassl_t *bev_ssl, unsigned short flag)
{
	if (bev_ssl) {
		if (!bev_ssl->cyassl_private.write_suspend) {
			be_cyassl_disable(bev_ssl, EV_WRITE);
		}
		bev_ssl->cyassl_private.write_suspend |= flag;
	}
}

static void be_cyassl_unsuspend_write(bufferevent_cyassl_t *bev_ssl, unsigned short flag)
{
	if (bev_ssl) {
		bev_ssl->cyassl_private.write_suspend &= ~flag;
		if (!bev_ssl->cyassl_private.write_suspend && (bev_ssl->enabled & EV_WRITE)) {
			be_cyassl_enable(bev_ssl, EV_WRITE);
		}
	}
}
	    
static int be_cyassl_finished_connecting(evutil_socket_t fd)
{
	int e;
	socklen_t len;

	len = sizeof(e);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0)
		return -1;

	if (e) {
		if (UTIL_ERR_CONNECT_RETRIABLE(e))
			return 0;
		errno = e;
		return -1;
	}

	return 1;
}

static void be_cyassl_read_cb(evutil_socket_t fd, short what, void *ctx)
{
	int howmuch = -1;
	bufferevent_cyassl_t* bev_ssl = ctx;
	short event = BEV_EVENT_READING;

	if (what == EV_TIMEOUT) {
		event |= BEV_EVENT_TIMEOUT;
		goto error;
	}

	if (bev_ssl->cyassl_private.wm_read.high) {
		howmuch = bev_ssl->cyassl_private.wm_read.high - evbuffer_get_length(bev_ssl->input);
		if (howmuch <= 0) {
			be_cyassl_suspend_read(bev_ssl, BEV_CYASSL_SUSPEND_WM);
			return;
		}
	}

	if (bev_ssl->cyassl_private.read_suspend) {
		return;
	}
	
	evbuffer_unfreeze(bev_ssl->input, 0);
	be_cyassl_read_buffer(bev_ssl, bev_ssl->input);
	evbuffer_freeze(bev_ssl->input, 0);

	// invoke users' read callback when finishing reading
	if (evbuffer_get_length(bev_ssl->input) >= bev_ssl->cyassl_private.wm_read.low) {
		be_cyassl_run_readcb(bev_ssl);
	}
	return;

error:
	bufferevent_cyassl_disable(bev_ssl, EV_READ);
	be_cyassl_run_eventcb(bev_ssl, event);
}

static void be_cyassl_write_cb(evutil_socket_t fd, short what, void *ctx)
{
	int length, status;
	bufferevent_cyassl_t *bev_ssl = ctx;
	short event = BEV_EVENT_WRITING;

	if (what == EV_TIMEOUT) {
		event |= BEV_EVENT_TIMEOUT;
		goto error;
	}

	switch (bev_ssl->state) {
		case BEV_CYASSL_TCP_CONNECTING: 
		{
			status = be_cyassl_finished_connecting(bev_ssl->fd);
			/* we need to fake the error if the connection was refused
		 	* immediately - usually connection to localhost on BSD */
			if (bev_ssl->connection_refused) {
				bev_ssl->connection_refused = 0;
				status = -1;
			}

			if (status == 0) {
				return;
			}

			if (status < 0) {
				event_del(&bev_ssl->ev_read);
				event_del(&bev_ssl->ev_write);
				be_cyassl_run_eventcb(bev_ssl, BEV_EVENT_ERROR);
				return;
			} else {
				bev_ssl->state = BEV_CYASSL_TCP_CONNECTED;
				goto ssl_connect;
			}
			break;
		}
		case BEV_CYASSL_TCP_CONNECTED: 
		{
			goto ssl_connect;
			break;
		}
		case BEV_CYASSL_CONNECTED: 
		{
			if (bev_ssl->cyassl_private.write_suspend) {
				return;
			}
			
			evbuffer_unfreeze(bev_ssl->output, 1);
			be_cyassl_write_buffer(bev_ssl, bev_ssl->output);
			evbuffer_freeze(bev_ssl->output, 1);

			length = evbuffer_get_length(bev_ssl->output);
			// no data to write, remove writeable event
			if ( length == 0 ) {
				event_del(&bev_ssl->ev_write);
			}

			// invoke users' write callback when finishing writing to cyassl
			if (evbuffer_get_length(bev_ssl->output) <= bev_ssl->cyassl_private.wm_write.low) {
				be_cyassl_run_writecb(bev_ssl);
			}
			return;
		}
		default:
		{
			event = BEV_EVENT_ERROR;
			goto error;
			break;
		}
	}

ssl_connect:
	bev_ssl->state = BEV_CYASSL_CONNECTING;
	status = CyaSSL_set_fd(bev_ssl->ssl, bev_ssl->fd);
	if (status != SSL_SUCCESS) {
		event = BEV_EVENT_ERROR;
		goto error;
	}

	status = be_cyassl_set_handshake_cb(bev_ssl, -1);
	if (status < 0) {
		event = BEV_EVENT_ERROR;
		goto error;
	} else {
		return;
	}

error:
	bufferevent_cyassl_disable(bev_ssl, EV_WRITE);
	be_cyassl_run_eventcb(bev_ssl, event);
}

static int be_cyassl_do_handshake(bufferevent_cyassl_t *bev_ssl)
{
	int r = 0;
	int err = 0;
	char err_str[128];

	switch (bev_ssl->state) {
		default:
		case BEV_CYASSL_CONNECTED:
			return 1;
		case BEV_CYASSL_CONNECTING:
			r = CyaSSL_connect(bev_ssl->ssl);
			break;
	}

	if (SSL_SUCCESS == r) {
		// ssl connect
		bev_ssl->state = BEV_CYASSL_CONNECTED;
		be_cyassl_set_connected_cb(bev_ssl, -1);
		be_cyassl_enable(bev_ssl, EV_READ);
		be_cyassl_run_eventcb(bev_ssl, BEV_EVENT_CONNECTED);
		return 1;
	} else {
		err = CyaSSL_get_error(bev_ssl->ssl, r);
		CyaSSL_ERR_error_string(err, err_str);

		switch (err) {
			case SSL_ERROR_WANT_READ:
				be_cyassl_disable(bev_ssl, EV_WRITE);
				be_cyassl_enable(bev_ssl, EV_READ);
				r = 0;
				break;
			case SSL_ERROR_WANT_WRITE:
				be_cyassl_disable(bev_ssl, EV_READ);
				be_cyassl_enable(bev_ssl, EV_WRITE);
				r = 0;
				break;
			default:
				return -1;
		}
		
		/* avoid busy loop */
		msleep(10);
		return r;
	}
}

static void be_cyassl_handshake_cb(evutil_socket_t fd, short what, void *ctx)
{
	bufferevent_cyassl_t *bev_ssl = ctx;

	if (what & EV_TIMEOUT) {
		be_cyassl_run_eventcb(bev_ssl, BEV_EVENT_TIMEOUT);
	} else {
		if ( -1 == be_cyassl_do_handshake(bev_ssl) ) {
			be_cyassl_run_eventcb(bev_ssl, BEV_EVENT_ERROR);
		}
	}
}

/* 2 for bev_sslection refused, 1 for bev_sslected, 0 for not yet, -1 for error. */
static int be_cyassl_socket_connect(evutil_socket_t *fd_ptr, struct sockaddr *sa, int socklen)
{
	int made_fd = 0;

	if (*fd_ptr < 0) {
		if ((*fd_ptr = socket(sa->sa_family, SOCK_STREAM, 0)) < 0)
			goto err;
		made_fd = 1;
		if (evutil_make_socket_nonblocking(*fd_ptr) < 0) {
			goto err;
		}
	}

	if (connect(*fd_ptr, sa, socklen) < 0) {
		int e = evutil_socket_geterror(*fd_ptr);
		if (UTIL_ERR_CONNECT_RETRIABLE(e))
			return 0;
		if (UTIL_ERR_CONNECT_REFUSED(e))
			return 2;
		goto err;
	} else {
		return 1;
	}

err:
	if (made_fd) {
		evutil_closesocket(*fd_ptr);
		*fd_ptr = -1;
	}
	return -1;
}

static void be_cyassl_outbuf_cb(struct evbuffer *buf, 
	const struct evbuffer_cb_info *cbinfo, 
	void *arg)
{
	bufferevent_cyassl_t *bev_ssl = arg;

	if (cbinfo->n_added &&
	    !event_pending(&bev_ssl->ev_write, EV_WRITE, NULL)) {
		/* Somebody added data to the buffer, and we would like to
		 * write, and we were not writing.  So, start writing. */
		if (be_cyassl_add_event(&bev_ssl->ev_write, &bev_ssl->timeout_write) == -1) {
		    /* Should we log this? */
			printf("event_add error, %s\n", strerror(errno));
		}
	}
}

static void be_cyassl_wm_input_cb(struct evbuffer *buf, 
	const struct evbuffer_cb_info *cbinfo, 
	void *arg)
{
	size_t size;
	bufferevent_cyassl_t *bev_ssl = arg;

	size = evbuffer_get_length(bev_ssl->input);
	if (bev_ssl->cyassl_private.wm_read.high) {
		if ( size < bev_ssl->cyassl_private.wm_read.high) {
			be_cyassl_unsuspend_read(bev_ssl, BEV_CYASSL_SUSPEND_WM);
		} else {
			be_cyassl_suspend_read(bev_ssl, BEV_CYASSL_SUSPEND_WM);
		}
	} else {
		be_cyassl_unsuspend_read(bev_ssl, BEV_CYASSL_SUSPEND_WM);
	}
}

static int be_cyassl_set_handshake_cb(bufferevent_cyassl_t *bev_ssl, evutil_socket_t fd)
{
	int r1 = 0, r2 = 0;
	
	if (!bev_ssl) {
		return -1;
	}

	if (fd < 0) {
		fd = CyaSSL_get_fd(bev_ssl->ssl);
	}

	if (event_pending(&bev_ssl->ev_read, EV_READ, NULL)) {
		event_del(&bev_ssl->ev_read);
	}

	if (event_pending(&bev_ssl->ev_write, EV_WRITE, NULL)) {
		event_del(&bev_ssl->ev_write);
	}
	
	event_assign(&bev_ssl->ev_read, bev_ssl->base, fd, EV_READ | EV_PERSIST, 
					be_cyassl_handshake_cb, bev_ssl);
	event_assign(&bev_ssl->ev_write, bev_ssl->base, fd, EV_WRITE | EV_PERSIST, 
					be_cyassl_handshake_cb, bev_ssl);
	if (fd >= 0) {
		r1 = be_cyassl_add_event(&bev_ssl->ev_read, &bev_ssl->timeout_read);
		r2 = be_cyassl_add_event(&bev_ssl->ev_write, &bev_ssl->timeout_write);
	}
	
	return (r1 < 0 || r2 < 0) ? -1 : 0;
}

static int be_cyassl_set_connected_cb(bufferevent_cyassl_t *bev_ssl, evutil_socket_t fd)
{
	int rpending = 0, wpending = 0, r1 = 0, r2 = 0;

	rpending = event_pending(&bev_ssl->ev_read, EV_READ, NULL);
	wpending = event_pending(&bev_ssl->ev_write, EV_WRITE, NULL);
	if (rpending) {
		event_del(&bev_ssl->ev_read);
	}
	if (wpending) {
		event_del(&bev_ssl->ev_write);
	}

	if (fd < 0) {
		fd = CyaSSL_get_fd(bev_ssl->ssl);
	}

	event_assign(&bev_ssl->ev_read, bev_ssl->base, fd, EV_READ | EV_PERSIST, 
				be_cyassl_read_cb, bev_ssl);
	event_assign(&bev_ssl->ev_write, bev_ssl->base, fd, EV_WRITE | EV_PERSIST, 
				be_cyassl_write_cb, bev_ssl);
	if (rpending) {
		r1 = be_cyassl_add_event(&bev_ssl->ev_read, &bev_ssl->timeout_read);
	}
	if (wpending) {
		r2 = be_cyassl_add_event(&bev_ssl->ev_write, &bev_ssl->timeout_write);
	}

	return (r1 < 0 || r2 < 0) ? -1 : 0;
}

static int be_cyassl_ctx_verify_cb(int preverify_ok, CYASSL_X509_STORE_CTX *ctx)
{
	int err;
	char err_str[128];

	err = CyaSSL_X509_STORE_CTX_get_error(ctx);
	CyaSSL_ERR_error_string(err, err_str);
	return preverify_ok;
}

static void be_cyassl_dns_cb(const struct addrinfo *res, void *arg)
{	
	bufferevent_cyassl_t* bev_ssl = arg;
	struct sockaddr_in addr;
	char ip_str[64];

	if (!res) {
		if (bev_ssl->event_cb) {
			bev_ssl->event_cb(bev_ssl, BEV_EVENT_DNSERROR, bev_ssl->arg);
		}
		return;
	}	// dns ok

	addr = *((struct sockaddr_in *)res->ai_addr);
	inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));

	bev_ssl->port = ntohs(addr.sin_port);
	snprintf(bev_ssl->host, sizeof(bev_ssl->host), "%s", ip_str);

	be_cyassl_unsuspend_read(bev_ssl, BEV_CYASSL_SUSPEND_LOOKUP);
	be_cyassl_unsuspend_write(bev_ssl, BEV_CYASSL_SUSPEND_LOOKUP);

	bufferevent_cyassl_socket_connect(bev_ssl, (struct sockaddr *)&addr, sizeof(struct sockaddr));
}

static int be_cyassl_ssl_init(bufferevent_cyassl_t *bev_ssl)
{
	if (!bev_ssl) {
		return -1;
	}

	bev_ssl->ctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
	if (!bev_ssl->ctx) {
		return -1;
	}

	CyaSSL_CTX_set_verify(bev_ssl->ctx, SSL_VERIFY_NONE, 0);
	bev_ssl->ssl = CyaSSL_new(bev_ssl->ctx);
	if (!bev_ssl->ssl) {
		return -1;
	}
	
	CyaSSL_set_using_nonblock(bev_ssl->ssl, 1);
	return 0;
}

int bufferevent_cyassl_ssl_init(bufferevent_cyassl_t *bev_ssl, 
	const char *rootCA_path, const char *domain_name)
{
	if (!bev_ssl) {
		return -1;
	}
	
	if (rootCA_path && rootCA_path[0]) {
		CyaSSL_CTX_set_verify(bev_ssl->ctx, SSL_VERIFY_PEER, be_cyassl_ctx_verify_cb);
		if ( CyaSSL_CTX_load_verify_locations(bev_ssl->ctx, rootCA_path, 0) != SSL_SUCCESS ) {
			printf("load rootCA:%s fail, %s\n", rootCA_path, strerror(errno));
			return -1;
		}

		if (domain_name && domain_name[0]) {
			CyaSSL_check_domain_name(bev_ssl->ssl, domain_name);
		}
	}

	return 0;
}

// read data from input buffer of cyassl
int bufferevent_cyassl_read(bufferevent_cyassl_t *bev_ssl, void *data, size_t size)
{	
	if (!bev_ssl || !data) {
		return -1;
	}

	return evbuffer_remove(bev_ssl->input, data, size);
}

// read data from input buffer of cyassl
int bufferevent_cyassl_read_buffer(bufferevent_cyassl_t *bev_ssl, struct evbuffer *evbuf)
{	
	if (!bev_ssl || !evbuf) {
		return -1;
	}
	
	return evbuffer_add_buffer(evbuf, bev_ssl->input);
}

// write data to output buffer of cyassl
int bufferevent_cyassl_write(bufferevent_cyassl_t *bev_ssl, const void *data, size_t size)
{	
	if (!bev_ssl || !data) {
		return -1;
	}

	return evbuffer_add(bev_ssl->output, data, size);
}

int bufferevent_cyassl_write_buffer(bufferevent_cyassl_t *bev_ssl, struct evbuffer *evbuf)
{	
	if (!bev_ssl || !evbuf) {
		return -1;
	}

	return evbuffer_add_buffer(bev_ssl->output, evbuf);
}

int bufferevent_cyassl_established(bufferevent_cyassl_t* bev_ssl)
{
	if ( bev_ssl && BEV_CYASSL_CONNECTED == bev_ssl->state ) {
		return 1;
	}

	return 0;
}

int bufferevent_cyassl_setcb(bufferevent_cyassl_t* bev_ssl, 
					bufferevent_cyassl_data_cb cb_read, 
					bufferevent_cyassl_data_cb cb_write, 
					bufferevent_cyassl_event_cb cb_event, 
					void *arg)
{
	if (!bev_ssl) {
		return -1;
	}

	bev_ssl->arg = arg;
	// EV_WRITE is enabled by default
	bev_ssl->enabled = EV_WRITE;

	if (cb_read) {
		bev_ssl->read_cb = cb_read;
		bev_ssl->enabled |= EV_READ;
	}

	if (cb_write) {
		bev_ssl->write_cb = cb_write;
	}

	if (cb_event) {
		bev_ssl->event_cb = cb_event;
	}

	return 0;
}

struct evbuffer* bufferevent_cyassl_get_input(bufferevent_cyassl_t* bev_ssl)
{
	if (bev_ssl) {
		return bev_ssl->input;
	} else {
		return NULL;
	}
}

struct evbuffer* bufferevent_cyassl_get_output(bufferevent_cyassl_t* bev_ssl)
{
	if (bev_ssl) {
		return bev_ssl->output;
	} else {
		return NULL;
	}
}

int bufferevent_cyassl_enable(bufferevent_cyassl_t *bev_ssl, short events)
{	
	if (!bev_ssl) {
		return -1;
	}

	bev_ssl->enabled |= events;
	return be_cyassl_enable(bev_ssl, events);
}

int bufferevent_cyassl_disable(bufferevent_cyassl_t *bev_ssl, short events)
{
	if (!bev_ssl) {
		return -1;
	}

	bev_ssl->enabled &= ~events;
	return be_cyassl_disable(bev_ssl, events);
}

int bufferevent_cyassl_set_timeouts(bufferevent_cyassl_t *bev_ssl, 
				const struct timeval *tv_read, 
				const struct timeval *tv_write)
{
	int r1 = 0, r2 = 0;

	if (tv_read) {
		bev_ssl->timeout_read = *tv_read;
	} else {
		evutil_timerclear(&bev_ssl->timeout_read);
	}

	if (tv_write) {
		bev_ssl->timeout_write = *tv_write;
	} else {
		evutil_timerclear(&bev_ssl->timeout_write);
	}

	if (event_pending(&bev_ssl->ev_read, EV_READ, NULL)) {
		r1 = be_cyassl_add_event(&bev_ssl->ev_read, &bev_ssl->timeout_read);
	}
	if (event_pending(&bev_ssl->ev_write, EV_WRITE, NULL)) {
		r2 = be_cyassl_add_event(&bev_ssl->ev_write, &bev_ssl->timeout_write);
	}

	return (r1 < 0 || r2 < 0) ? -1 : 0;
}

void bufferevent_cyassl_setwatermark(bufferevent_cyassl_t *bev_ssl, short events, 
		size_t lowmark, size_t highmark)
{
	if (!bev_ssl) {
		return;
	}
	
	if (events & EV_WRITE) {
		bev_ssl->cyassl_private.wm_write.low = lowmark;
		bev_ssl->cyassl_private.wm_write.high = highmark;
	}

	if (events & EV_READ) {
		bev_ssl->cyassl_private.wm_read.low = lowmark;
		bev_ssl->cyassl_private.wm_read.high = highmark;

		if (highmark) {
			if (evbuffer_get_length(bev_ssl->input) > highmark) {
				be_cyassl_suspend_read(bev_ssl, BEV_CYASSL_SUSPEND_WM);
			} else if (evbuffer_get_length(bev_ssl->input) < highmark) {
				be_cyassl_unsuspend_read(bev_ssl, BEV_CYASSL_SUSPEND_WM);
			}
		} else {
			be_cyassl_unsuspend_read(bev_ssl, BEV_CYASSL_SUSPEND_WM);
		}
	}
}

int bufferevent_cyassl_free(bufferevent_cyassl_t *bev_ssl)
{
	if (!bev_ssl) {
		return 0;
	}

	if (event_pending(&bev_ssl->ev_read, EV_READ, NULL)) {
		event_del(&bev_ssl->ev_read);
	}
	if (event_pending(&bev_ssl->ev_write, EV_WRITE, NULL)) {
		event_del(&bev_ssl->ev_write);
	}
	event_debug_unassign(&bev_ssl->ev_read);
	event_debug_unassign(&bev_ssl->ev_write);

	if (bev_ssl->evaddrinfo){
		evaddrinfo_free(bev_ssl->evaddrinfo);
	}
	if (bev_ssl->input) {
		evbuffer_free(bev_ssl->input);
	}
	if (bev_ssl->output) {
		evbuffer_free(bev_ssl->output);
	}
	if (bev_ssl->ssl) {
		CyaSSL_shutdown(bev_ssl->ssl);
		CyaSSL_free(bev_ssl->ssl);
	}
	if (bev_ssl->fd > 0) {
		close(bev_ssl->fd);
	}
	if (bev_ssl->ctx) {
		CyaSSL_CTX_free(bev_ssl->ctx);
	}
	
	memset(bev_ssl, 0, sizeof(*bev_ssl));
	free(bev_ssl);
	return 0;
}

bufferevent_cyassl_t* bufferevent_cyassl_socket_new(void *evbase, evutil_socket_t fd)
{
	if (!evbase) {
		return NULL;
	}

	bufferevent_cyassl_t* bev_ssl = calloc(1, sizeof(bufferevent_cyassl_t));
	if (!bev_ssl) {
		return NULL;
	}

	if ((bev_ssl->input = evbuffer_new()) == NULL) {
		goto failed;
	}
	if ((bev_ssl->output = evbuffer_new()) == NULL) {
		goto failed;
	}

	bev_ssl->fd = fd;
	bev_ssl->base = evbase;
	if (fd < 0) {
		bev_ssl->state = BEV_CYASSL_DISCONNECTED;
	} else {
		bev_ssl->state = BEV_CYASSL_TCP_CONNECTED;
	}
	
	if (be_cyassl_ssl_init(bev_ssl) < 0) {
		goto failed;
	}
	event_assign(&bev_ssl->ev_read, bev_ssl->base, bev_ssl->fd, EV_READ|EV_PERSIST, 
				be_cyassl_read_cb, bev_ssl);
	event_assign(&bev_ssl->ev_write, bev_ssl->base, bev_ssl->fd, EV_WRITE|EV_PERSIST, 
				be_cyassl_write_cb, bev_ssl);

	evbuffer_add_cb(bev_ssl->output, be_cyassl_outbuf_cb, bev_ssl);
	evbuffer_add_cb(bev_ssl->input, be_cyassl_wm_input_cb, bev_ssl);
	evbuffer_freeze(bev_ssl->input, 0);
	evbuffer_freeze(bev_ssl->output, 1);

	// write event is enabled by default
	bev_ssl->enabled = EV_WRITE;
	return bev_ssl;

failed:
	bufferevent_cyassl_free(bev_ssl);
	return NULL;
}

int bufferevent_cyassl_socket_connect(bufferevent_cyassl_t *bev_ssl, struct sockaddr *addr, int socklen)
{
	int r = 0;
	evutil_socket_t fd;

	if (!bev_ssl || !addr || socklen <= 0) {
		goto failed;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		goto failed;
	}
	if (evutil_make_socket_nonblocking(fd) < 0) {
		goto failed;
	}

	r = be_cyassl_socket_connect(&fd, addr, socklen);
	if (r < 0) {
		close(fd);
		goto failed;
	}

	bev_ssl->fd = fd;
	event_assign(&bev_ssl->ev_write, bev_ssl->base, fd, EV_WRITE|EV_PERSIST, 
			be_cyassl_write_cb, bev_ssl);

	if (r == 0) {
		bev_ssl->state = BEV_CYASSL_TCP_CONNECTING;
		if (be_cyassl_enable(bev_ssl, EV_WRITE)) {
			goto failed;
		}
	} else if (r == 1) {
		// tcp connection finished
		bev_ssl->state = BEV_CYASSL_TCP_CONNECTED;
		event_active(&bev_ssl->ev_write, EV_WRITE, 1);
	} else {
		bev_ssl->connection_refused = 1;
		bev_ssl->state = BEV_CYASSL_TCP_CONNECTING;
		event_active(&bev_ssl->ev_write, EV_WRITE, 1);
	}

	return 0;

failed:
	bev_ssl->state = BEV_CYASSL_DISCONNECTED;
	
	if (bev_ssl->event_cb) {
		bev_ssl->event_cb(bev_ssl, BEV_EVENT_ERROR, bev_ssl->arg);
	}
	return -1;
}

/* Only support TCP for SSL connection */
int bufferevent_cyassl_socket_connect_hostname(bufferevent_cyassl_t *bev_ssl, char *host, int port)
{
	char port_str[8];
	struct sockaddr_in addr;

	if (!bev_ssl || !host || !host[0]) {
		return -1;
	}

	snprintf(bev_ssl->host, sizeof(bev_ssl->host), "%s", host);
	bev_ssl->port = port;
	bev_ssl->state = BEV_CYASSL_TCP_CONNECTING;

	if (!isdigit(host[0])) {
		snprintf(port_str, sizeof(port_str), "%d", port);
		evaddrinfo_reload_nameserver();

		be_cyassl_suspend_read(bev_ssl, BEV_CYASSL_SUSPEND_LOOKUP);
		be_cyassl_suspend_write(bev_ssl, BEV_CYASSL_SUSPEND_LOOKUP);
		
		bev_ssl->evaddrinfo = evaddrinfo_new(bev_ssl->base, host, 
			port_str, 13, be_cyassl_dns_cb, bev_ssl);

		if (!bev_ssl->evaddrinfo) {
			bev_ssl->state = BEV_CYASSL_DISCONNECTED;
			if (bev_ssl->event_cb) {
				bev_ssl->event_cb(bev_ssl, BEV_EVENT_ERROR, bev_ssl->arg);
			}

			be_cyassl_unsuspend_read(bev_ssl, BEV_CYASSL_SUSPEND_LOOKUP);
			be_cyassl_unsuspend_write(bev_ssl, BEV_CYASSL_SUSPEND_LOOKUP);
			return -1;
		} else {
			return 0;
		}
	} else {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = inet_addr(host);
		
		return bufferevent_cyassl_socket_connect(bev_ssl, (struct sockaddr *)&addr, sizeof(struct sockaddr));
	}
}


