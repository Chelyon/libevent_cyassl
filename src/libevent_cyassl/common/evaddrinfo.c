#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "evaddrinfo.h"
#ifndef WIN32
#include <resolv.h>	/* for res_init */
#endif

#define EVADDRINFO_BUSYLOOP_MSTIMEOUT	50
#define EVADDRINFO_HOST_SIZE			128
#define EVADDRINFO_SERVICE_SIZE			64

struct evaddrinfo_s
{
	struct event*		ev;
	char				host[EVADDRINFO_HOST_SIZE];
	char				service[EVADDRINFO_SERVICE_SIZE];
	int					timeout_msec;
	struct addrinfo*	res;
	evaddrinfo_cb		dns_handler;
	void*				arg;

	MUTEX_DEFINE		(lock);
	int					ref;	
};

struct dns_tbl_entry {
	int status;// 0, free; 1, used;
	time_t expire_time;// in second

	char host[EVADDRINFO_HOST_SIZE];// hostname, no port included, e.g.: jp-control-beta.tplinkcloud.com
	char addr[EVADDRINFO_HOST_SIZE];// IPv4 address, e.g.: 192.168.1.2
};

#ifndef DNS_ENTRY_LIVE_TIME
#define DNS_ENTRY_LIVE_TIME	  180 // in second, 3min
#endif
#define DNS_ENTRY_MAX		  32

// in windows, you have no way to init a CriticalSection when define it.
// dont touch the lock if dns cache disabled(default)
static MUTEX_DEFINE			 (dns_tbl_lock);
static struct dns_tbl_entry	  dns_tbl[DNS_ENTRY_MAX];
static int					  dns_cache_enabled;


void evaddrinfo_enable_dns_cache()
{
	// in windows, you have no way to init a CriticalSection when define it
	MUTEX_INIT(dns_tbl_lock);
	dns_cache_enabled = 1;
}

void evaddrinfo_clear_dns_cache_all()
{
	int i;

	if (!dns_cache_enabled) {
		return;
	}

	MUTEX_LOCK(dns_tbl_lock);
	for (i = 0; i < DNS_ENTRY_MAX; ++i) {
		dns_tbl[i].status = 0;
	}
	MUTEX_UNLOCK(dns_tbl_lock);
}

void evaddrinfo_clear_dns_cache_single(const char *hostname)
{
	int i;

	if ( !dns_cache_enabled || !hostname || !hostname[0] ) {
		return;
	}

	MUTEX_LOCK(dns_tbl_lock);
	for (i = 0; i < DNS_ENTRY_MAX; ++i) {
		if (!dns_tbl[i].status) {
			continue;
		}

		if ( !strcmp(dns_tbl[i].host, hostname) ) {
			dns_tbl[i].status = 0;
			printf("dns cache cleared: [%s] -> [%s]\n", 
				dns_tbl[i].host, dns_tbl[i].addr);
		}
	}
	MUTEX_UNLOCK(dns_tbl_lock);
}

// lock dns table by callee
static struct addrinfo *dns_tbl_clone_addrinfo(struct dns_tbl_entry *entry, 
			const char *host, const char *service)
{
	// different system may implement getaddrinfo()/freeaddrinfo() differently, see 'see also'.
	// so we'd better not to generate the structure addrinfo ourselves.
	// we use getaddrinfo() with an host argument which actually is the string format of an ip address.
	// because it is an ip address actually, no dns query will be sent out.
	//
	// see also:
	// www.cs.cmu.edu/afs/cs/academic/class/15213-f00/unpv12e/libgai/freeaddrinfo.c
	// ftp.stu.edu.tw/BSD/OpenBSD/src/lib/libc/net/freeaddrinfo.c
	struct addrinfo hints, *res = NULL;
	int err;

	if ( !entry || !host || strcmp(entry->host, host) ) {
		return NULL;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if ((err = getaddrinfo(entry->addr, service, &hints, &res)) != 0) {
		printf("getaddrinfo('%s:%s') failed: %d; %s\n", 
			entry->addr, service, err, gai_strerror(err));
		return NULL;
	}

	return res;
}

static struct dns_tbl_entry *dns_tbl_find(char *host)
{
	int i;
	time_t now;

	if (!host) {
		return NULL;
	}

	MUTEX_LOCK(dns_tbl_lock);
	now = time(NULL);
	for (i = 0; i < DNS_ENTRY_MAX; ++i) {
		if (!dns_tbl[i].status) {
			continue;
		}

		if ( difftime(now, dns_tbl[i].expire_time) >= 0 ) {
			dns_tbl[i].status = 0;
			continue;
		}

		if ( strcmp(dns_tbl[i].host, host) ) {
			continue;
		}

		MUTEX_UNLOCK(dns_tbl_lock);
		return &dns_tbl[i];
	}
	MUTEX_UNLOCK(dns_tbl_lock);

	return NULL;
}

static int dns_tbl_add(struct addrinfo *addrinfo, char *host)
{
	int i, firstfree, oldest, pos;
	struct sockaddr_in *sin;

	if ( !host || !addrinfo || 
		addrinfo->ai_family != AF_INET || 
		strlen(host) >= EVADDRINFO_HOST_SIZE ) {
		return -1;
	}

	MUTEX_LOCK(dns_tbl_lock);
	firstfree = -1;
	oldest = -1;
	for (i = 0; i < DNS_ENTRY_MAX; ++i) {
		if (!dns_tbl[i].status) {
			if ( firstfree < 0 ) {
				firstfree = i;
			}
			continue;
		}

		if ( strcmp(dns_tbl[i].host, host) ) {
			if ( oldest < 0 || 
				dns_tbl[i].expire_time < dns_tbl[oldest].expire_time ) {//dns_tcb[i] is earlier to expire
				oldest = i;
				continue;
			}
		}

		break;
	}

	if ( i < DNS_ENTRY_MAX ) {
		pos = i;
	} else if ( firstfree >= 0 ) {
		pos = firstfree;
	} else {
		pos = oldest;
	}

	sin = (struct sockaddr_in *)addrinfo->ai_addr;
	evutil_inet_ntop(addrinfo->ai_family, &sin->sin_addr, 
						dns_tbl[pos].addr, sizeof(dns_tbl[pos].addr));
	memcpy(dns_tbl[pos].host, host, strlen(host));//len has been checked
	dns_tbl[pos].status = 1;
	dns_tbl[pos].expire_time = time(NULL) + DNS_ENTRY_LIVE_TIME;//in second
	MUTEX_UNLOCK(dns_tbl_lock);
	return 0;
}


static void timeout_cb(evutil_socket_t fd, short event, void* arg)
{
	evaddrinfo_t* info = (evaddrinfo_t*)arg;

	info->timeout_msec -= EVADDRINFO_BUSYLOOP_MSTIMEOUT;
	if ( info->res || info->timeout_msec <= 0 ) {
		/* make sure 'thread_getaddrinfo' do not touch this ev later */
		event_free(info->ev);
		info->ev = NULL;
		info->dns_handler(info->res, info->arg);
		return;
	}
}


static void evaddrinfo_free_internal(evaddrinfo_t* info)
{
	if (info->ev) {
		event_free(info->ev);
	}
	if (info->res) {
		freeaddrinfo(info->res);
	}
	MUTEX_DESTROY(info->lock);
	free(info);
	printf("evaddrinfo_free_internal %p\n", info);
}


static THREAD_RETURN thread_getaddrinfo(void* arg)
{
	evaddrinfo_t* info = (evaddrinfo_t*)arg;
	struct addrinfo hints;
	int do_free = 0, err;
	struct dns_tbl_entry *dns_tbl_entry;
	struct sockaddr_in sin;
	char buf[32] = {0};

#ifndef WIN32
	pthread_detach(pthread_self());
#endif
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	info->res = NULL;
	if (dns_cache_enabled) {
		dns_tbl_entry = dns_tbl_find(info->host);
		if (dns_tbl_entry) {
			info->res = dns_tbl_clone_addrinfo(dns_tbl_entry, info->host, info->service);
		}
	}

	if (!info->res) {
		if ((err = getaddrinfo(info->host, info->service, &hints, &info->res)) != 0) {
			printf("getaddrinfo('%s:%s') failed: %d; %s\n", 
				info->host, info->service, err, gai_strerror(err));
			goto DONE;
		}
		
		if (dns_cache_enabled) {
			dns_tbl_add(info->res, info->host);
		}
	}

	sin = *((struct sockaddr_in *)(info->res->ai_addr));
	evutil_inet_ntop(AF_INET, &sin.sin_addr, buf, sizeof(buf));
	printf("getaddrinfo('%s:%s') '%s:%d'\n", 
		info->host, info->service, buf, ntohs(sin.sin_port));

DONE:
	MUTEX_LOCK(info->lock);
	info->ref--;
	if ( info->ref <= 0 ) {
		do_free = 1;
	}
	MUTEX_UNLOCK(info->lock);

	/* DNS resolve failed */
	if (!info->res) { 
		/* disable busy loop */
		info->timeout_msec = 0;
	}
	if (do_free) {
		evaddrinfo_free_internal(info);
	}

	return 0;
}


void evaddrinfo_free(evaddrinfo_t* info)
{
	int free_pending = 0;

	if (!info) {
		return;
	}

	MUTEX_LOCK(info->lock);
	info->ref--;
	if ( info->ref > 0 ) {
		free_pending = 1;
	}
	MUTEX_UNLOCK(info->lock);

	if (info->ev) {
		/* make sure 'thread_getaddrinfo' do not touch this ev later */
		event_free(info->ev);
		info->ev = NULL;
	}
	if (!free_pending) {
		evaddrinfo_free_internal(info);
	}
}


evaddrinfo_t* evaddrinfo_new(struct event_base* base, 
		const char* host, const char* service, 
	   	int timeout_sec, evaddrinfo_cb dns_handler, void* arg)
{
	evaddrinfo_t* info;
	pthread_t thread;
	struct timeval tv;

	if ( !base || !host || timeout_sec < 1 || !dns_handler ) {
		return NULL;
	}

	info = (evaddrinfo_t*)calloc(1, sizeof(evaddrinfo_t));
	if (!info) {
		return NULL;
	}

	/* set timeout event */
	info->ev = event_new(base, -1, EV_TIMEOUT|EV_PERSIST, timeout_cb, info);
	if (!info->ev) {
		goto FAILED;
	}

	tv.tv_sec = 0;
	tv.tv_usec = EVADDRINFO_BUSYLOOP_MSTIMEOUT*1000;
	if ( event_add(info->ev, &tv) != 0 ) {
		goto FAILED;
	}
	MUTEX_INIT(info->lock);
	info->dns_handler = dns_handler;
	info->arg = arg;
	info->timeout_msec = timeout_sec*1000;
	info->ref = 2;
	snprintf(info->host, sizeof(info->host), "%s", host);
	snprintf(info->service, sizeof(info->service), "%s", 
				(service && service[0]) ? service : "0");

	if ( create_thread(thread, thread_getaddrinfo, info) != 0 ) {
		MUTEX_DESTROY(info->lock);
		goto FAILED;
	}
#ifdef WIN32
	CloseHandle(thread);
#endif

	printf("evaddrinfo_new %p\n", info);
	return info;
FAILED:
	if (info->ev) {
		event_free(info->ev);
	}
	free(info);

	return NULL;
}


int evaddrinfo_reload_nameserver()
{
#if defined WIN32
	HMODULE mod_dnsapi;
	int (*ReloadNameserver)();
	int ret = -1;
	
	mod_dnsapi = LoadLibrary(TEXT("dnsapi.dll"));
	if (!mod_dnsapi) {
	    return -1;
	}
	
	*(FARPROC *) &ReloadNameserver =
	        GetProcAddress(mod_dnsapi, "DnsFlushResolverCache");
	if ( ReloadNameserver && ReloadNameserver() ) {
	    ret = 0;
	}

	FreeLibrary(mod_dnsapi);
	return ret;
#elif defined ARM
	/* res_init does not work on ARM */
	_res.options &= ~RES_INIT;
	return 0;
#else
	/* unix/linux/apple/android all provides res_init() */
	return res_init();
#endif
}


#ifdef UNIT_TEST
static void dns_handler(const struct addrinfo* res, void* arg)
{
	struct in_addr addr;

	if (res) {
		addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
		printf("resolve OK '%s'\n", inet_ntoa(addr));
	} else {
		printf("resolve Failed\n");
	}
}

int main(int argc, char** argv)
{
	int timeout = argc > 2 ? atoi(argv[2]) : 7;
	struct event_base* base = event_base_new();
	evaddrinfo_t* info = evaddrinfo_new(base, argv[1], NULL, timeout, dns_handler, NULL);

	if (!info) {
		puts("evaddrinfo_new failed");
		return -1;
	}

	printf("async getaddrinfo...\n");
	event_base_dispatch(base);
	evaddrinfo_free(info);
	sleep(60);

	return 0;
}

#endif



