/******************************************************************************
 *
 * Copyright (c) 2014 TP-LINK Technologies CO.,LTD.
 * All rights reserved.
 *
 * FILE NAME  :   platform.h
 * VERSION    :   1.0
 * DESCRIPTION:   platform independent MACROs and interfaces
 *
 * AUTHOR     :   ChenXingqi <chenxingqi@tp-link.net>
 * CREATE DATE:   11/03/2014
 *
 * HISTORY    :
 * 01   11/03/2014  ChenXingqi create
 *
 ******************************************************************************/

#ifndef __PLATFORM_H_
#define __PLATFORM_H_

#ifdef WIN32
/***************** win32 *****************/
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
/* socket error compatibility */
#define msleep(x) Sleep(x)
#define strtok_r strtok_s
#define strdup _strdup
#define snprintf(__s,__n,__fmt,...) _snprintf_s((__s),(__n),(__n)-1,__fmt, __VA_ARGS__)
//#define sscanf sscanf_s// sscanf_s has broken regular expression support
#define localtime_r(__utc,__res) localtime_s((__res),(__utc))
typedef int socklen_t;

#define MUTEX_DEFINE(__lock) CRITICAL_SECTION __lock
#define MUTEX_DEFINIT(__lock) CRITICAL_SECTION __lock
#define MUTEX_INIT(__lock) InitializeCriticalSection(&(__lock))
#define MUTEX_DESTROY(__lock) DeleteCriticalSection(&(__lock))
#define MUTEX_LOCK(__lock) EnterCriticalSection(&(__lock))
#define MUTEX_UNLOCK(__lock) LeaveCriticalSection(&(__lock))

#define sys_errno	GetLastError()
#define sock_errno	WSAGetLastError()
#define sock_func_will_block(__ret) ((-1 == (__ret)) && (WSAEWOULDBLOCK == WSAGetLastError() || \
			WSAEINPROGRESS == WSAGetLastError()))
#define evutil_make_socket_blocking(__fd) do{int opt=0;ioctlsocket(__fd, FIONBIO, &opt);}while(0)
#define evutil_shutdown_socket_send(__fd) do{shutdown(__fd, SD_SEND);}while(0)
#define evutil_shutdown_socket_recv(__fd) do{shutdown(__fd, SD_RECEIVE);}while(0)
#define evutil_shutdown_socket_both(__fd) do{shutdown(__fd, SD_BOTH);}while(0)

#define pthread_t HANDLE
#define THREAD_RETURN DWORD WINAPI
#define create_thread(handle, pfunc, arg) \
	((handle=CreateThread(NULL, 0, pfunc, arg, 0, NULL)) ? 0 : -1)
#define exit_thread(exitcode) ExitThread(exitcode)

#pragma comment (lib, "ws2_32.lib" )
#else
/***************** *nix *****************/
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define msleep(x) usleep(1000*(x))

#include <pthread.h>
#define MUTEX_DEFINE(__lock) pthread_mutex_t __lock
#define MUTEX_DEFINIT(__lock) pthread_mutex_t __lock=PTHREAD_MUTEX_INITIALIZER
#define MUTEX_INIT(__lock) pthread_mutex_init(&(__lock),NULL)
#define MUTEX_DESTROY(__lock) pthread_mutex_destroy(&(__lock))
#define MUTEX_LOCK(__lock) pthread_mutex_lock(&(__lock))
#define MUTEX_UNLOCK(__lock) pthread_mutex_unlock(&(__lock))

#define sys_errno	errno
#define sock_errno	errno
#define sock_func_will_block(__ret) ((-1==__ret) && (EWOULDBLOCK==errno || EAGAIN==errno || EINTR==errno))
#define evutil_make_socket_blocking(__fd) fcntl(__fd, F_SETFL, fcntl(__fd, F_GETFL)&~O_NONBLOCK)
#define evutil_shutdown_socket_send(__fd) do{shutdown(__fd, SHUT_WR);}while(0)
#define evutil_shutdown_socket_recv(__fd) do{shutdown(__fd, SHUT_RD);}while(0)
#define evutil_shutdown_socket_both(__fd) do{shutdown(__fd, SHUT_RDWR);}while(0)

#define THREAD_RETURN void*
#define create_thread(handle, pfunc, arg) pthread_create(&handle, NULL, pfunc, arg)
#define exit_thread(exitcode) pthread_exit((void*)(exitcode))

#endif


/* common cross-platform macros */
#ifdef ANDROID_DEBUG
#include <android/log.h>
#define LOG_TAG "NAT_P2P"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGE(...)
#endif

#define MAX2(a,b) ((a)>(b)?(a):(b))
#define MIN2(a,b) ((a)<(b)?(a):(b))

// args:
//	tv: type of struct timeval (NOTE: not pointer)
//	ms: milli second
#define MilliSec2Timeval(tv, ms) do{\
	tv.tv_sec = (ms) / 1000;\
	tv.tv_usec = (ms) * 1000 % 1000000;\
}while(0)

#endif

