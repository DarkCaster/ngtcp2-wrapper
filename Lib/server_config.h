#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include "config.h"

#ifdef __cplusplus
#ifdef HAVE_INTTYPES_H
#include <cinttypes>
#else
#include <cstdint>
#endif
#else
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#include <stdint.h>
#endif
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

union sockaddr_union {
		struct sockaddr_storage storage;
		struct sockaddr sa;
		struct sockaddr_in6 in6;
		struct sockaddr_in in;
};

struct Address {
		socklen_t len;
		union sockaddr_union su;
};

struct ServerConfig {
		struct Address preferred_ipv4_addr;
		struct Address preferred_ipv6_addr;
		// tx_loss_prob is probability of losing outgoing packet.
		double tx_loss_prob;
		// rx_loss_prob is probability of losing incoming packet.
		double rx_loss_prob;
		// ciphers is the list of enabled ciphers.
		const char *ciphers;
		// groups is the list of supported groups.
		const char *groups;
		// timeout is an idle timeout for QUIC connection.
		uint32_t timeout;
		// port is the port number which server listens on for incoming
		// connections.
		uint16_t port;
		// quiet suppresses the output normally shown except for the error
		// messages.
		uint8_t quiet;
		// show_secret is true if transport secrets should be printed out.
		uint8_t show_secret;
		// validate_addr is true if server requires address validation.
		uint8_t validate_addr;
};

void server_config_set_default(struct ServerConfig *config);

#ifdef __cplusplus
}
#endif

#endif
