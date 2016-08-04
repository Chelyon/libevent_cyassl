#ifndef _CONNECTION_CYASSL_H_
#define _CONNECTION_CYASSL_H_

/**
   @file bufferevent_cyassl.h

  Functions for buffering data for network sending or receiving.  Bufferevent_cyassl
  are higher level than evbuffers: each has an underlying evbuffer for reading
  and one for writing, and callbacks that are invoked under certain
  circumstances.

  A bufferevent_cyassl provides input and output buffers that get filled and
  drained automatically.  The user of a bufferevent_cyassl no longer deals
  directly with the I/O, but instead is reading from input and writing
  to output buffers.

  Once initialized, the bufferevent_cyassl structure can be used repeatedly
  with bufferevent_cyassl_enable() and bufferevent_cyassl_disable().

  When reading is enabled, the bufferevent_cyassl will try to read from the
  file descriptor onto its input buffer, and and call the read callback.
  When writing is enabled, the bufferevent_cyassl will try to write data onto its
  file descriptor when writing is enabled, and call the write callback
  when the output buffer is sufficiently drained.

  A bufferevent_cyassl uses the cyassl library to send and receive data over an 
  encrypted connection. Created with
  bufferevent_cyassl_socket_new().

 */
 
#include <event2/util.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event_struct.h>
#include <event2/bufferevent_struct.h>

#include <cyassl/ssl.h>
#include <cyassl/ctaocrypt/asn.h>

/* extend BEV_EVENT_* flags in event2/bufferevent.h */
#ifndef BEV_EVENT_DNSERROR
#define BEV_EVENT_DNSERROR		0x0100
#endif

/* the definition of bufferevent_cyassl structure */
typedef struct bufferevent_cyassl_s bufferevent_cyassl_t;

/**
   A read or write callback for a bufferevent_cyassl.

   The read callback is triggered when new data arrives in the input
   buffer and the amount of readable data exceed the low watermark
   which is 0 by default.

   The write callback is triggered if the write buffer has been
   exhausted or fell below its low watermark.

   @param bev_ssl the bufferevent_cyassl that triggered the callback
   @param ctx the user-specified context for this bufferevent_cyassl
 */
typedef void (*bufferevent_cyassl_data_cb)(bufferevent_cyassl_t *bev_ssl, void *ctx);

/**
   An event/error callback for a bufferevent_cyassl.

   The event callback is triggered if either an EOF condition or another
   unrecoverable error was encountered.

   @param bev_ssl the bufferevent_cyassl for which the error condition was reached
   @param what a conjunction of flags: BEV_EVENT_READING or BEV_EVENT_WRITING
	  to indicate if the error was encountered on the read or write path,
	  and one of the following flags: BEV_EVENT_EOF, BEV_EVENT_ERROR,
	  BEV_EVENT_TIMEOUT, BEV_EVENT_CONNECTED, BEV_EVENT_DNSERROR.

   @param ctx the user-specified context for this bufferevent_cyassl
*/
typedef void (*bufferevent_cyassl_event_cb)(bufferevent_cyassl_t *bev_ssl, short what, void *ctx);

/**
  Create a new bufferevent_cyassl to send/receive its data over a CYASSL * on a socket

  @param base An event_base to use to detect reading and writing
  @param fd the file descriptor from which encrypted data is read and written to.
	    This file descriptor is not allowed to be a pipe(2).
	    It is safe to set the fd to -1, so long as you set it with bufferevent_cyassl_socket_connect() 
      or bufferevent_cyassl_socket_connect_hostname() later.
  @return a pointer to a newly allocated bufferevent_cyassl struct, or NULL if an
	  error occurred
  @see bufferevent_cyassl_free()
  */
bufferevent_cyassl_t *bufferevent_cyassl_socket_new(void *evbase, evutil_socket_t fd);

/**
   Launch a connect() attempt for setting up an underlying socket for bufferevent_cyassl.

   When the connect succeeds, it will start setting up a cyassl connection

   We allocate a new socket here and make it nonblocking before we begin for bufferevent_cyassl.

   If no address is provided, the eventcb will be invoked with BEV_EVENT_ERROR set.

   @param bev_ssl an existing bufferevent_cyassl allocated with
       bufferevent_cyassl_socket_new().
   @param addr the address we should connect to
   @param socklen The length of the address
   @return 0 on success, -1 on failure.
 */
int bufferevent_cyassl_socket_connect(bufferevent_cyassl_t *bev_ssl, struct sockaddr *addr, int socklen);

/**
   Resolve the hostname 'hostname' and connect to it as with
   bufferevent_cyassl_socket_connect().

   @param bev_ssl An existing bufferevent_cyassl allocated with bufferevent_cyassl_socket_new()
   @param hostname The hostname to resolve; see below for notes on recognized
      formats
   @param port The port to connect to on the resolved address.
   @return 0 if successful, -1 on failure.

   Recognized hostname formats are:

       www.example.com	(hostname)
       
 */
int bufferevent_cyassl_socket_connect_hostname(bufferevent_cyassl_t *bev_ssl, char *host, int port);

/**
  Deallocate the storage associated with a bufferevent_cyassl structure.

  @param bev_ssl the bufferevent_cyassl structure to be freed.
  */
int bufferevent_cyassl_free(bufferevent_cyassl_t *bev_ssl);

/**
  Initialize cyassl, setting rootCA path and domain_name for verifying server's certificate.

  @param bev_ssl the bufferevent_cyassl structure for which to set ssl verification.
  @param rootCA_path the rootCA path for verification, it won't verify if it's NULL.
  @param domain_name the domain name which to be checked for verification.
  */
int bufferevent_cyassl_ssl_init(bufferevent_cyassl_t *bev_ssl, 
	const char *rootCA_path, const char *domain_name);

/**
  Read data from a bufferevent_cyassl buffer.

  The bufferevent_cyassl_read() function is used to read data from the input buffer.

  @param bev_ssl the bufferevent_cyassl to be read from
  @param data pointer to a buffer that will store the data
  @param size the size of the data buffer, in bytes
  @return the amount of data read, in bytes.
 */
int bufferevent_cyassl_read(bufferevent_cyassl_t *bev_ssl, void *data, size_t size);

/**
  Read data from a bufferevent_cyassl buffer into an evbuffer.	 This avoids
  memory copies.

  @param bev_ssl the bufferevent_cyassl to be read from
  @param evbuf the evbuffer to which to add data
  @return 0 if successful, or -1 if an error occurred.
 */
int bufferevent_cyassl_read_buffer(bufferevent_cyassl_t *bev_ssl, struct evbuffer *evbuf);

/**
  Write data to a bufferevent_cyassl buffer.

  The bufferevent_cyassl_write() function can be used to write data to the 
  CYASSL * .  The data is appended to the output buffer and written to the
  CYASSL * automatically as it becomes available for writing.

  @param bev_ssl the bufferevent_cyassl to be written to
  @param data a pointer to the data to be written
  @param size the length of the data, in bytes
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_cyassl_write_buffer()
  */
int bufferevent_cyassl_write(bufferevent_cyassl_t *bev_ssl, const void *data, size_t size);

/**
  Write data from an evbuffer to a bufferevent_cyassl buffer.	The evbuffer is
  being drained as a result.

  @param bev_ssl the bufferevent_cyassl to be written to
  @param evbuf the evbuffer to be written
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_cyassl_write()
 */
int bufferevent_cyassl_write_buffer(bufferevent_cyassl_t *bev_ssl, struct evbuffer *evbuf);

/**
  Get the result that whether the bufferevent_cyassl connection is finished or not

  @param bev_ssl the bufferevent_cyassl which set up the cyassl connection
  @return 1 if connected, or 0 if not
 */
int bufferevent_cyassl_established(bufferevent_cyassl_t *bev_ssl);

/**
  Changes the callbacks for a bufferevent_cyassl.

  @param bev_ssl the bufferevent_cyassl object for which to change callbacks
  @param cb_read callback to invoke when there is data to be read, or NULL if
	 no callback is desired
  @param cb_write callback to invoke when the file descriptor is ready for
	 writing, or NULL if no callback is desired
  @param cb_event callback to invoke when there is an event on the file
	 descriptor
  @param cbarg an argument that will be supplied to each of the callbacks
	 (cb_read, cb_write, and cb_event)
  */
int bufferevent_cyassl_setcb(bufferevent_cyassl_t *bev_ssl, 
					bufferevent_cyassl_data_cb cb_read, 
					bufferevent_cyassl_data_cb cb_write, 
					bufferevent_cyassl_event_cb cb_event, 
					void *cbarg);

/**
  Set the read and write timeout for a bufferevent_cyassl.

  A bufferevent_cyassl's timeout will fire the first time that the indicated
  amount of time has elapsed since a successful read or write operation,
  during which the bufferevent_cyassl was trying to read or write.

  (In other words, if reading or writing is disabled, or if the
  bufferevent's read or write operation has been suspended because
  there's no data to write, or not enough banwidth, or so on, the
  timeout isn't active.  The timeout only becomes active when we we're
  willing to actually read or write.)

  Calling bufferevent_cyassl_enable or setting a timeout for a bufferevent_cyassl
  whose timeout is already pending resets its timeout.

  If the timeout elapses, the corresponding operation (EV_READ or
  EV_WRITE) becomes disabled until you re-enable it again.  The
  bufferevent_cyassl's event callback is called with the
  BEV_EVENT_TIMEOUT|BEV_EVENT_READING or
  BEV_EVENT_TIMEOUT|BEV_EVENT_WRITING.

  @param bev_ssl the bufferevent to be modified
  @param tv_read the read timeout, or NULL
  @param tv_write the write timeout, or NULL
 */
int bufferevent_cyassl_set_timeouts(bufferevent_cyassl_t *bev_ssl, 
				const struct timeval *tv_read, 
				const struct timeval *tv_write);

/**
  Sets the watermarks for read and write events.

  On input, a bufferevent_cyassl does not invoke the user read callback unless
  there is at least low watermark data in the buffer.	If the read buffer is 
  beyond the high watermark, the bufferevent_cyassl stops reading from the network.

  On output, the user write callback is invoked whenever the buffered data
  falls below the low watermark.  Filters that write to this bufev will try
  not to write more bytes to this buffer than the high watermark would allow,
  except when flushing.

  @param bev_ssl the bufferevent to be modified
  @param events EV_READ, EV_WRITE or both
  @param lowmark the lower watermark to set
  @param highmark the high watermark to set
*/
void bufferevent_cyassl_setwatermark(bufferevent_cyassl_t *bev_ssl, short events, 
				size_t lowmark, size_t highmark);

/**
   Returns the input buffer.

   The user MUST NOT set the callback on this buffer.

   @param bev_ssl the bufferevent_cyassl from which to get the evbuffer
   @return the evbuffer object for the input buffer
 */
struct evbuffer *bufferevent_cyassl_get_input(bufferevent_cyassl_t *bev_ssl);

/**
   Returns the output buffer.

   The user MUST NOT set the callback on this buffer.

   When filters are being used, the filters need to be manually
   triggered if the output buffer was manipulated.

   @param bev_ssl the bufferevent_cyassl from which to get the evbuffer
   @return the evbuffer object for the output buffer
 */
struct evbuffer *bufferevent_cyassl_get_output(bufferevent_cyassl_t *bev_ssl);

/**
  Enable a bufferevent_cyassl.

  @param bev_ssl the bufferevent_cyassl to be enabled
  @param events any combination of EV_READ | EV_WRITE.
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_cyassl_disable()
 */
int bufferevent_cyassl_enable(bufferevent_cyassl_t *bev_ssl, short events);

/**
  Disable a bufferevent_cyassl.

  @param bev_ssl the bufferevent_cyassl to be disabled
  @param events any combination of EV_READ | EV_WRITE.
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_cyassl_enable()
 */
int bufferevent_cyassl_disable(bufferevent_cyassl_t *bev_ssl, short events);

#endif
