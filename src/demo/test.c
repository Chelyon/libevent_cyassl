#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>

#include <event2/event.h>
#include <bufferevent_cyassl.h>

#define LEN_MAX_HOSTNAME	256

typedef struct client_context_s {
	struct event_base *base;
	struct event *ev_timer;

	char	server_host[LEN_MAX_HOSTNAME];
	int		server_port;
	char	certpath[LEN_MAX_HOSTNAME];

	struct event *ev_sigint;
	struct event *ev_sigterm;
} client_ctx_t;


static void event_timer_cb(evutil_socket_t fd, short what, void *ctx)
{
	/**
		  If it's a server program, using evconnlistener provided by libevent for 
		listening incoming connections will keep event_base loop.
		  Otherwise, you should add a persist timer to event_base to keep it loop,
		which is this callback used for.
	 */
}

static void client_ctx_free(client_ctx_t *client_ctx)
{
	if (client_ctx) {
		if (client_ctx->base) {
			event_base_free(client_ctx->base);
		}

		if (client_ctx->ev_timer) {
			event_free(client_ctx->ev_timer);
		}

		if (client_ctx->ev_sigint) {
			event_free(client_ctx->ev_sigint);
		}

		if (client_ctx->ev_sigterm) {
			event_free(client_ctx->ev_sigterm);
		}

		memset(client_ctx, 0, sizeof(*client_ctx));
		free(client_ctx);
	}
}

static void signal_quit_cb(evutil_socket_t sig, short events, void *ctx)
{
	client_ctx_t *client_ctx = ctx;
	struct timeval delay = {0, 5*1000};

	printf("got signal %d, events:%#X\n", sig, events);
	event_base_loopexit(client_ctx->base, &delay);
}

static client_ctx_t *client_ctx_new()
{
	struct timeval tv = {600, 0};
	client_ctx_t *client_ctx = calloc(1, sizeof(client_ctx_t));

	if (client_ctx) {
		client_ctx->base = event_base_new();
		if (!client_ctx->base) {
			goto failed;
		}

		client_ctx->ev_timer = event_new(client_ctx->base, -1, 
			EV_PERSIST, event_timer_cb, NULL);
		if (!client_ctx->ev_timer) {
			goto failed;
		}

		// register signal handler
		client_ctx->ev_sigint = 
			evsignal_new(client_ctx->base, SIGINT, signal_quit_cb, client_ctx);
		client_ctx->ev_sigterm = 
			evsignal_new(client_ctx->base, SIGTERM, signal_quit_cb, client_ctx);
		if (!client_ctx->ev_sigint || !client_ctx->ev_sigterm) {
			goto failed;
		}

		event_add(client_ctx->ev_timer, &tv);
	}
	return client_ctx;

failed:
	client_ctx_free(client_ctx);
	return NULL;
}

static void client_ctx_dump(client_ctx_t *client_ctx)
{
	if (client_ctx) {
		printf("[client context dump] "
				"server_host:%s, server_port:%d, certpath:%s\r\n",
				client_ctx->server_host, client_ctx->server_port, 
				client_ctx->certpath);
	}
}

static int client_ctx_init_option(client_ctx_t *client_ctx, 
				int argc, char **argv)
{
	int opt = 0;
	int long_index = 0;

	static struct option long_opts[] = {
		{"server-address",	required_argument,	0,  's'},
		{"server-port",		required_argument,	0,  'r'},
		{"server-certpath",	required_argument,	0,  'c'},
		{0,					0,					0,   0 }
	};

	if (client_ctx == NULL) {
		return -1;
	}

	while ( (opt = getopt_long(argc, argv, "l:p:s:r:c:", 
		long_opts, &long_index)) != -1 )
	{
		switch (opt) {
			case 's':
				if ( strlen(optarg) >= sizeof(client_ctx->server_host) ) {
					printf("server host %s too long\n", optarg);
					return -1;
				}
				strncpy(client_ctx->server_host, optarg, sizeof(client_ctx->server_host));
				break;

			case 'r':
				client_ctx->server_port = atoi(optarg);
				break;

			case 'c':
				if ( strlen(optarg) >= sizeof(client_ctx->certpath) ) {
					printf("server certificate %s too long\n", optarg);
					return -1;
				}
				strncpy(client_ctx->certpath, optarg, sizeof(client_ctx->certpath));
				break;

			default:
				printf("invalid parameter\n");
				break;
		}
	}

	return 0;
}

static void connection_read_cb(bufferevent_cyassl_t *bev_ssl, void *ctx)
{
	/**
		Note: bufferevent_cyassl only support edge trigger, you'd better 
	  read off the data in the input buffer at a time.
	 */

	char buf[1024] = {0};

	bufferevent_cyassl_read(bev_ssl, buf, sizeof(buf)-1);
	printf("response from server:%s\n", buf);

	// close connection
	bufferevent_cyassl_free(bev_ssl);
}

static void connection_write_cb(bufferevent_cyassl_t *bev_ssl, void *ctx)
{
	printf("client message has been sent to server\n");
}

static void connection_event_cb(bufferevent_cyassl_t *bev_ssl, short events, void *ctx)
{
	printf("events:%#X\n", events);

	if ( events & BEV_EVENT_CONNECTED ) {
		printf("cyassl connected to server, sending message to server...\n");

		char msg[32];
		int len = snprintf(msg, sizeof(msg), "hello world, I am Chelyon");
		bufferevent_cyassl_write(bev_ssl, msg, len);
		return;
	} else {
		printf("cyassl fail to connect to server, %s\n", strerror(errno));
	}

	bufferevent_cyassl_free(bev_ssl);
}

int main(int argc, char **argv)
{
	int ret = 0;
	bufferevent_cyassl_t *bev_ssl = NULL;

	if ( daemon(0, 1) < 0 ) {
		printf("cannot run as daemon, %s\n", strerror(errno));
		return -1;
	}

	signal(SIGPIPE, SIG_IGN);

	client_ctx_t *client_ctx = client_ctx_new();
	if (client_ctx == NULL) {
		printf("client ctx new fail\n");
		return -1;
	}

	ret = client_ctx_init_option(client_ctx, argc, argv);
	if ( ret < 0 ) {
		printf("client ctx init option fail\n");
		goto exit;
	}

	client_ctx_dump(client_ctx);
	bev_ssl = bufferevent_cyassl_socket_new(client_ctx->base, -1);
	if (!bev_ssl) {
		goto exit;
	}

	bufferevent_cyassl_setcb(bev_ssl, 
							connection_read_cb, 
							connection_write_cb, 
							connection_event_cb, 
							(void *)bev_ssl);

	bufferevent_cyassl_ssl_init(bev_ssl, client_ctx->certpath, "*.tplinkcloud.com");
	bufferevent_cyassl_socket_connect_hostname(bev_ssl, client_ctx->server_host, 
												client_ctx->server_port);

	event_base_dispatch(client_ctx->base);

exit:
	printf("ssl_test exit\n");
	client_ctx_free(client_ctx);
	return -1;
}