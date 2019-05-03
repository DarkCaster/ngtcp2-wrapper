#ifndef CLIENT_CONFIG_H
#define CLIENT_CONFIG_H

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

#ifdef __cplusplus
}
#endif

#endif
