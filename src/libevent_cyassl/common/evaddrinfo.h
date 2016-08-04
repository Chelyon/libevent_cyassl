/**
 * A libevent based async getaddrinfo implementation, using threads
 */
#ifndef __EVADDRINFO_H__
#define __EVADDRINFO_H__

#include "platform.h"
#include "event2/event.h"
#include "event2/util.h"

typedef struct evaddrinfo_s evaddrinfo_t;

typedef void (*evaddrinfo_cb)(const struct addrinfo* res, void* arg);

evaddrinfo_t* evaddrinfo_new(struct event_base* base, 
		const char* host, const char* service, 
	   	int timeout_sec, evaddrinfo_cb dns_handler, void* arg);

extern void evaddrinfo_free(evaddrinfo_t* info);

/* return: 0 on success, -1 on fail */
extern int  evaddrinfo_reload_nameserver();

/* do dns cache or not. default: not */
extern void evaddrinfo_enable_dns_cache();

/* clear all entry in the dns cache table */
extern void evaddrinfo_clear_dns_cache_all();

/* clear the entry specified by `hostname' in the dns cache table */
extern void evaddrinfo_clear_dns_cache_single(const char *hostname);

#endif

