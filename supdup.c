/*
* Supdup backend
*/

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "putty.h"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

/*
 * TTYOPT FUNCTION BITS (36-bit bitmasks)
*/                
#define TOALT	0200000000000					//  Characters 0175 and 0176 are converted to altmode (0033) on input
#define TOCLC   0100000000000					//  (user option bit) Convert lower-case input to upper-case
#define TOERS   0040000000000					//  Selective erase is supported
#define TOMVB   0010000000000					//  Backspacing is supported
#define TOSAI   0004000000000					//  Stanford/ITS extended ASCII graphics character set is supported
#define TOSA1   0002000000000					//  (user option bit) Characters 0001-0037 displayed using Stanford/ITS chars
#define TOOVR   0001000000000					//  Overprinting is supported
#define TOMVU   0000400000000					//  Moving cursor upwards is supported
#define TOMOR   0000200000000					//  (user option bit) System should provide **MORE** processing
#define TOROL   0000100000000					//  (user option bit) Terminal should scroll instead of wrapping
#define TOLWR   0000020000000					//  Lowercase characters are supported
#define TOFCI   0000010000000					//  Terminal can generate CONTROL and META characters
#define TOLID   0000002000000					//  Line insert/delete operations supported
#define TOCID   0000001000000					//  Character insert/delete operations supported
#define TPCBS   0000000000040					//  Terminal is using the "intelligent terminal protocol" (must be on)
#define TPORS   0000000000010					//  Server should process output resets

// Initialization words (36-bit constants)
#define WORDS   0777773000000					//  Negative number of config words to send (6) in high 18 bits
#define TCTYP	0000000000007					//  Defines the terminal type (MUST be 7)
#define TTYROL  0000000000001					//  Scroll amount for terminal (1 line at a time)


typedef struct supdup_tag 
{
	const struct plug_function_table *fn;
	/* the above field _must_ be first in the structure */

	Socket s;
	int closed_on_socket_error;

	void *frontend;
	void *ldisc;
	int term_width, term_height;

	long ttyopt;
	long tcmxv;
	long tcmxh;	

	int sent_location;

	Conf *conf;

	int bufsize;

	enum
	{
		CONNECTING,		// waiting for %TDNOP from server after sending connection params
		CONNECTED		// %TDNOP received, connected.
	} state;

	Pinger pinger;
} *Supdup;

#define SUPDUP_MAX_BACKLOG 4096

static void c_write(Supdup supdup, char *buf, int len)
{
	int backlog;
	backlog = from_backend(supdup->frontend, 0, buf, len);
	sk_set_frozen(supdup->s, backlog > SUPDUP_MAX_BACKLOG);
}

static void supdup_send_location(Supdup supdup)
{
	char locHeader[] = { 0300, 0302 };

	char* locString = conf_get_str(supdup->conf, CONF_supdup_location);

	sk_write(supdup->s, locHeader, sizeof(locHeader));
	sk_write(supdup->s, locString, strlen(locString) + 1);	// include NULL terminator
}

static void do_supdup_read(Supdup supdup, char *buf, int len)
{
	char *outbuf = NULL;
	int outbuflen = 0, outbufsize = 0;

#define ADDTOBUF(c) do { \
    if (outbuflen >= outbufsize) { \
	outbufsize = outbuflen + 256; \
        outbuf = sresize(outbuf, outbufsize, char); \
    } \
    outbuf[outbuflen++] = (c); \
} while (0)

	while (len--) 
	{
		int c = (unsigned char)*buf++;

		switch (supdup->state) {
		case CONNECTING:
			// "Following the transmission of the terminal options by the user, the server
			//  should respond with an ASCII greeting message, terminated with a  %TDNOP
			//  code..."
			if (TDNOP == c)
			{
				// Greeting done, switch to the CONNECTED state.
				supdup->state = CONNECTED;						
			}
			else
			{
				// Forward the greeting message (which is straight ASCII, no controls) on so it gets displayed
				// TODO: filter out only printable chars?
				ADDTOBUF(c);
			}
			break;

		case CONNECTED:			
			// "All transmissions from the server after the %TDNOP [see above]
			//  are either printing characters or virtual terminal display codes."
			// Forward these on to the frontend which will decide what to do with them.
			ADDTOBUF(c);

			/*
			* Hack to make Symbolics Genera SUPDUP happy:
			* Wait until after we're connected (finished the initial handshake and have
			* gotten additional data) before sending the location string.  For some
			* reason doing so earlier causes the Symbolics SUPDUP to end up in an odd state.
			*/
			if (!supdup->sent_location)
			{
				supdup_send_location(supdup);
				supdup->sent_location = 1;
			}

			break;
		}
	}

	if (outbuflen)
	{
		c_write(supdup, outbuf, outbuflen);
	}

	sfree(outbuf);
}

static void supdup_log(Plug plug, int type, SockAddr addr, int port,
	const char *error_msg, int error_code)
{
	Supdup supdup = (Supdup)plug;
	char addrbuf[256], *msg;

	sk_getaddr(addr, addrbuf, lenof(addrbuf));

	if (type == 0)
		msg = dupprintf("Connecting to %s port %d", addrbuf, port);
	else
		msg = dupprintf("Failed to connect to %s: %s", addrbuf, error_msg);

	logevent(supdup->frontend, msg);
	sfree(msg);
}

static int supdup_closing(Plug plug, const char *error_msg, int error_code,
	int calling_back)
{
	Supdup supdup = (Supdup)plug;

	/*
	* We don't implement independent EOF in each direction for Telnet
	* connections; as soon as we get word that the remote side has
	* sent us EOF, we wind up the whole connection.
	*/

	if (supdup->s) {
		sk_close(supdup->s);
		supdup->s = NULL;
		if (error_msg)
			supdup->closed_on_socket_error = TRUE;
		notify_remote_exit(supdup->frontend);
	}
	if (error_msg) {
		logevent(supdup->frontend, error_msg);
		connection_fatal(supdup->frontend, "%s", error_msg);
	}
	/* Otherwise, the remote side closed the connection normally. */
	return 0;
}

static int supdup_receive(Plug plug, int urgent, char *data, int len)
{
	Supdup supdup = (Supdup)plug;

	do_supdup_read(supdup, data, len);
	return 1;
}

static void supdup_sent(Plug plug, int bufsize)
{
	Supdup supdup = (Supdup)plug;
	supdup->bufsize = bufsize;
}

static void supdup_send_36bits(Supdup supdup, unsigned long long thirtysix)
{
	// 
	// From RFC734:
	// "Each word is sent through the 8-bit connection as six
	//  6-bit bytes, most-significant first."
	//
	// Split the 36-bit word into 6 6-bit "bytes", packed into
	// 8-bit bytes and send, most-significant byte first.
	//
	unsigned long long mask = 0770000000000;		// 6 bit mask
	for (int i = 5; i >= 0; i--)
	{
		char sixBits = (thirtysix & mask) >> (i * 6);

		sk_write(supdup->s, &sixBits, 1);
		mask = mask >> 6;
	}
}

static void supdup_send_config(Supdup supdup)
{
	supdup_send_36bits(supdup, WORDS);				// negative length
	supdup_send_36bits(supdup, TCTYP);				// terminal type
	supdup_send_36bits(supdup, supdup->ttyopt);		// options
	supdup_send_36bits(supdup, supdup->tcmxv);		// height
	supdup_send_36bits(supdup, supdup->tcmxh);		// width
	supdup_send_36bits(supdup, TTYROL);				// scroll amount	
}

/*
* Called to set up the Supdup connection.
*
* Returns an error message, or NULL on success.
*
* Also places the canonical host name into `realhost'. It must be
* freed by the caller.
*/
static const char *supdup_init(void *frontend_handle, void **backend_handle,
	Conf *conf, char *host, int port,
	char **realhost, int nodelay, int keepalive)
{
	static const struct plug_function_table fn_table = {
		supdup_log,
		supdup_closing,
		supdup_receive,
		supdup_sent
	};
	SockAddr addr;
	const char *err;
	Supdup supdup;
	char *loghost;
	int addressfamily;

	supdup = snew(struct supdup_tag);
	supdup->fn = &fn_table;
	supdup->conf = conf_copy(conf);
	supdup->s = NULL;
	supdup->closed_on_socket_error = FALSE;	
	supdup->frontend = frontend_handle;
	supdup->term_width = conf_get_int(supdup->conf, CONF_width);
	supdup->term_height = conf_get_int(supdup->conf, CONF_height);	
	supdup->ldisc = NULL;
	supdup->pinger = NULL;
	supdup->sent_location = 0;
	*backend_handle = supdup;

	/*
	* Try to find host.
	*/
	{
		char *buf;
		addressfamily = conf_get_int(supdup->conf, CONF_addressfamily);
		buf = dupprintf("Looking up host \"%s\"%s", host,
			(addressfamily == ADDRTYPE_IPV4 ? " (IPv4)" :
				(addressfamily == ADDRTYPE_IPV6 ? " (IPv6)" :
					"")));
		logevent(supdup->frontend, buf);
		sfree(buf);
	}
	addr = name_lookup(host, port, realhost, supdup->conf, addressfamily);
	if ((err = sk_addr_error(addr)) != NULL) {
		sk_addr_free(addr);
		return err;
	}

	if (port < 0)
		port = 0137;		       /* default supdup port */

	/*
	* Open socket.
	*/
	supdup->s = new_connection(addr, *realhost, port, 0, 1,
		nodelay, keepalive, (Plug)supdup, supdup->conf);
	if ((err = sk_socket_error(supdup->s)) != NULL)
		return err;

	supdup->pinger = pinger_new(supdup->conf, &supdup_backend, supdup);	

	/*
	* We can send special commands from the start.
	*/
	update_specials_menu(supdup->frontend);

	/*
	* loghost overrides realhost, if specified.
	*/
	loghost = conf_get_str(supdup->conf, CONF_loghost);
	if (*loghost) {
		char *colon;

		sfree(*realhost);
		*realhost = dupstr(loghost);

		colon = host_strrchr(*realhost, ':');
		if (colon)
			*colon++ = '\0';
	}

	/*
	* Set up TTYOPTS based on config
	*/
	int more_processing = conf_get_int(supdup->conf, CONF_supdup_more);
	int scrolling = conf_get_int(supdup->conf, CONF_supdup_scroll);	

	supdup->ttyopt = TOERS |
					 TOMVB |
					 TOSAI |
					 TOSA1 |
					 TOMVU |
					 TOLWR |
					 TOFCI |
					 TOLID |
					 TOCID |
					 TPCBS |
					 (scrolling ? TOROL : 0) |
		             (more_processing ? TOMOR : 0) |
					 TPORS;

	supdup->tcmxh = supdup->term_width - 1;		// -1 "..one column is used to indicate line continuation."
	supdup->tcmxv = supdup->term_height;

	/*
	* Send our configuration words to the server
	*/
	supdup_send_config(supdup);

	/*
	* Send our location data to the server
	*/
	//supdup_send_location(supdup);

	/*
	* We next expect a connection message followed by %TDNOP from the server
	*/
	supdup->state = CONNECTING;

	return NULL;
}


static void supdup_free(void *handle)
{
	Supdup supdup = (Supdup)handle;

	//sfree(supdup->sb_buf);
	if (supdup->s)
		sk_close(supdup->s);
	if (supdup->pinger)
		pinger_free(supdup->pinger);
	conf_free(supdup->conf);
	sfree(supdup);
}
/*
* Reconfigure the Supdup backend.
*/
static void supdup_reconfig(void *handle, Conf *conf)
{
	/* Nothing to do; SUPDUP cannot be reconfigured while running. */
}

/*
* Called to send data down the Supdup connection.
*/
static int supdup_send(void *handle, char *buf, int len)
{
	Supdup supdup = (Supdup)handle;
	unsigned char *p, *end;
	
	if (supdup->s == NULL)
		return 0;

	supdup->bufsize = sk_write(supdup->s, buf, len);

	return supdup->bufsize;
}

/*
* Called to query the current socket sendability status.
*/
static int supdup_sendbuffer(void *handle)
{
	Supdup supdup = (Supdup)handle;
	return supdup->bufsize;
}

/*
* Called to set the size of the window from Supdup's POV.
*/
static void supdup_size(void *handle, int width, int height)
{
	
	Supdup supdup = (Supdup)handle;
	
	supdup->term_width = width;
    supdup->term_height = height;

	//
	// SUPDUP does not support resizing the
	// terminal after connection establishment.
	//
}

/*
* Send Telnet special codes.
*/
static void supdup_special(void *handle, Telnet_Special code)
{
	
}

static const struct telnet_special *supdup_get_specials(void *handle)
{
	return NULL;
}

static int supdup_connected(void *handle)
{
	Supdup supdup = (Supdup)handle;
	return supdup->s != NULL;
}

static int supdup_sendok(void *handle)
{	
	return 1;
}

static void supdup_unthrottle(void *handle, int backlog)
{
	Supdup supdup = (Supdup)handle;
	sk_set_frozen(supdup->s, backlog > SUPDUP_MAX_BACKLOG);
}

static int supdup_ldisc(void *handle, int option)
{	
	Supdup supdup = (Supdup)handle;
	if (option == LD_ECHO)
	{
		// SUPDUP never performs local echoing.
		return FALSE;
	}
	
	return FALSE;
}

static void supdup_provide_ldisc(void *handle, void *ldisc)
{
	Supdup supdup = (Supdup)handle;
	supdup->ldisc = ldisc;
}

static void supdup_provide_logctx(void *handle, void *logctx)
{
	/* This is a stub. */
}

static int supdup_exitcode(void *handle)
{
	Supdup supdup = (Supdup)handle;
	if (supdup->s != NULL)
		return -1;                     /* still connected */
	else if (supdup->closed_on_socket_error)
		return INT_MAX;     /* a socket error counts as an unclean exit */
	else
		/* Supdup doesn't transmit exit codes back to the client */
		return 0;
}

/*
* cfg_info for Dupdup does nothing at all.
*/
static int supdup_cfg_info(void *handle)
{
	return 0;
}

Backend supdup_backend = {
	supdup_init,
	supdup_free,
	supdup_reconfig,
	supdup_send,
	supdup_sendbuffer,
	supdup_size,
	supdup_special,
	supdup_get_specials,
	supdup_connected,
	supdup_exitcode,
	supdup_sendok,
	supdup_ldisc,
	supdup_provide_ldisc,
	supdup_provide_logctx,
	supdup_unthrottle,
	supdup_cfg_info,
	"supdup",
	PROT_SUPDUP,
	0137
};
