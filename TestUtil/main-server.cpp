#include "config.h"
#include <getopt.h>
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include "server.h"
#include <netdb.h>
#include <unistd.h>
#include "debug.h"
#include <fstream>
#include <openssl/bio.h>
#include <openssl/err.h>

int transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
                              unsigned int context, const unsigned char *in,
                              size_t inlen, X509 *x, size_t chainidx, int *al,
                              void *parse_arg) {
	if (context != SSL_EXT_CLIENT_HELLO) {
		*al = SSL_AD_ILLEGAL_PARAMETER;
		return -1;
	}

	auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
	auto conn = h->conn();

	int rv;

	ngtcp2_transport_params params;

	rv = ngtcp2_decode_transport_params(
	    &params, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, in, inlen);
	if (rv != 0) {
		std::cerr << "ngtcp2_decode_transport_params: " << ngtcp2_strerror(rv)
		          << std::endl;
		*al = SSL_AD_ILLEGAL_PARAMETER;
		return -1;
	}

	rv = ngtcp2_conn_set_remote_transport_params(conn, &params);
	if (rv != 0) {
		std::cerr << "ngtcp2_conn_set_remote_transport_params: "
		          << ngtcp2_strerror(rv) << std::endl;
		*al = SSL_AD_ILLEGAL_PARAMETER;
		return -1;
	}

	return 1;
}

void transport_params_free_cb(SSL *ssl, unsigned int ext_type,
                              unsigned int context, const unsigned char *out,
                              void *add_arg) {
	delete[] const_cast<unsigned char *>(out);
}

int transport_params_add_cb(SSL *ssl, unsigned int ext_type,
                            unsigned int context, const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx, int *al,
                            void *add_arg) {
	auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
	auto conn = h->conn();

	ngtcp2_transport_params params;

	ngtcp2_conn_get_local_transport_params(conn, &params);

	constexpr size_t bufsize = 512;
	auto buf = std::make_unique<uint8_t[]>(bufsize);

	auto nwrite = ngtcp2_encode_transport_params(
	    buf.get(), bufsize, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
	    &params);
	if (nwrite < 0) {
		std::cerr << "ngtcp2_encode_transport_params: "
		          << ngtcp2_strerror(static_cast<int>(nwrite)) << std::endl;
		*al = SSL_AD_INTERNAL_ERROR;
		return -1;
	}

	*out = buf.release();
	*outlen = static_cast<size_t>(nwrite);

	return 1;
}

int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
	auto h = static_cast<Handler *>(SSL_get_app_data(ssl));
	const uint8_t *alpn;
	size_t alpnlen;
	auto version = ngtcp2_conn_get_negotiated_version(h->conn());

	switch (version) {
		case NGTCP2_PROTO_VER_D19:
			alpn = reinterpret_cast<const uint8_t *>(NGTCP2_ALPN_H3);
		alpnlen = str_size(NGTCP2_ALPN_H3);
			break;
		default:
			if (!svConfig.quiet) {
			std::cerr << "Unexpected quic protocol version: " << std::hex << "0x"
			          << version << std::endl;
		}
			return SSL_TLSEXT_ERR_NOACK;
	}

	for (auto p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1) {
		if (std::equal(alpn, alpn + alpnlen, p)) {
			*out = p + 1;
			*outlen = *p;
			return SSL_TLSEXT_ERR_OK;
		}
	}

	if (!svConfig.quiet) {
		std::cerr << "Client did not present ALPN " << NGTCP2_ALPN_H3 + 1
		          << std::endl;
	}

	return SSL_TLSEXT_ERR_NOACK;
}

SSL_CTX *create_ssl_ctx(const char *private_key_file, const char *cert_file) {
	auto ssl_ctx = SSL_CTX_new(TLS_method());

	constexpr auto ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
	                          SSL_OP_SINGLE_ECDH_USE |
	                          SSL_OP_CIPHER_SERVER_PREFERENCE |
	                          SSL_OP_NO_ANTI_REPLAY;

	SSL_CTX_set_options(ssl_ctx, ssl_opts);
	SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

	if (SSL_CTX_set_ciphersuites(ssl_ctx, svConfig.ciphers) != 1) {
		std::cerr << "SSL_CTX_set_ciphersuites: "
		          << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		goto fail;
	}

	if (SSL_CTX_set1_groups_list(ssl_ctx, svConfig.groups) != 1) {
		std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
		goto fail;
	}

	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_QUIC_HACK);

	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

	SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, nullptr);

	SSL_CTX_set_default_verify_paths(ssl_ctx);

	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file,
	                                SSL_FILETYPE_PEM) != 1) {
		std::cerr << "SSL_CTX_use_PrivateKey_file: "
		          << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		goto fail;
	}

	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
		std::cerr << "SSL_CTX_use_certificate_file: "
		          << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		goto fail;
	}

	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		std::cerr << "SSL_CTX_check_private_key: "
		          << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		goto fail;
	}

	if (SSL_CTX_add_custom_ext(
	        ssl_ctx, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
	        SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
	        transport_params_add_cb, transport_params_free_cb, nullptr,
	        transport_params_parse_cb, nullptr) != 1) {
		std::cerr << "SSL_CTX_add_custom_ext(NGTCP2_TLSEXT_QUIC_TRANSPORT_"
		             "PARAMETERS) failed: "
		          << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		goto fail;
	}

	SSL_CTX_set_max_early_data(ssl_ctx, std::numeric_limits<uint32_t>::max());

	return ssl_ctx;

fail:
	SSL_CTX_free(ssl_ctx);
	return nullptr;
}


std::ofstream keylog_file;
void keylog_callback(const SSL *ssl, const char *line) {
	keylog_file.write(line, strlen(line));
	keylog_file.put('\n');
	keylog_file.flush();
}

int parse_host_port(Address &dest, int af, const char *first,
                    const char *last) {
	if (std::distance(first, last) == 0) {
		return -1;
	}

	const char *host_begin, *host_end, *it;
	if (*first == '[') {
		host_begin = first + 1;
		it = std::find(host_begin, last, ']');
		if (it == last) {
			return -1;
		}
		host_end = it;
		++it;
		if (it == last || *it != ':') {
			return -1;
		}
	} else {
		host_begin = first;
		it = std::find(host_begin, last, ':');
		if (it == last) {
			return -1;
		}
		host_end = it;
	}

	if (++it == last) {
		return -1;
	}
	auto svc_begin = it;

	std::array<char, NI_MAXHOST> host;
	*std::copy(host_begin, host_end, std::begin(host)) = '\0';

	addrinfo hints{}, *res;
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;

	auto rv = getaddrinfo(host.data(), svc_begin, &hints, &res);
	if (rv != 0) {
		std::cerr << "getaddrinfo: [" << host.data() << "]:" << svc_begin << ": "
		          << gai_strerror(rv) << std::endl;
		return -1;
	}

	dest.len = res->ai_addrlen;
	memcpy(&dest.su, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	return 0;
}

void print_usage() {
	std::cerr << "Usage: server [OPTIONS] <ADDR> <PORT> <PRIVATE_KEY_FILE> "
							 "<CERTIFICATE_FILE>"
						<< std::endl;
}

void print_help() {
	print_usage();

	server_config_set_default(&svConfig);

	std::cout << R"(
	<ADDR>      Address to listen to.  '*' binds to any address.
	<PORT>      Port
	<PRIVATE_KEY_FILE>
							Path to private key file
	<CERTIFICATE_FILE>
							Path to certificate file
Options:
	-t, --tx-loss=<P>
							The probability of losing outgoing packets.  <P> must be
							[0.0, 1.0],  inclusive.  0.0 means no  packet loss.  1.0
							means 100% packet loss.
	-r, --rx-loss=<P>
							The probability of losing incoming packets.  <P> must be
							[0.0, 1.0],  inclusive.  0.0 means no  packet loss.  1.0
							means 100% packet loss.
	--ciphers=<CIPHERS>
							Specify the cipher suite list to enable.
							Default: )"
	          << svConfig.ciphers << R"(
	--groups=<GROUPS>
							Specify the supported groups.
							Default: )"
	          << svConfig.groups << R"(
	-d, --htdocs=<PATH>
							Specify document root.  If this option is not specified,
							the document root is the current working directory.
	-q, --quiet Suppress debug output.
	-s, --show-secret
							Print out secrets unless --quiet is used.
	--timeout=<T>
							Specify idle timeout in milliseconds.
							Default: )"
	          << svConfig.timeout << R"(
	-V, --validate-addr
							Perform address validation.
	--preferred-ipv4-addr=<ADDR>:<PORT>
							Specify preferred IPv4 address and port.
	--preferred-ipv6-addr=<ADDR>:<PORT>
							Specify preferred IPv6 address and port.  A numeric IPv6
							address  must   be  enclosed  by  '['   and  ']'  (e.g.,
							[::1]:8443)
	-h, --help  Display this help and exit.
)";
}

int main(int argc, char **argv) {
	server_config_set_default(&svConfig);

	for (;;) {
		static int flag = 0;
		constexpr static option long_opts[] = {
				{"help", no_argument, nullptr, 'h'},
				{"tx-loss", required_argument, nullptr, 't'},
				{"rx-loss", required_argument, nullptr, 'r'},
				{"htdocs", required_argument, nullptr, 'd'},
				{"quiet", no_argument, nullptr, 'q'},
				{"show-secret", no_argument, nullptr, 's'},
				{"validate-addr", no_argument, nullptr, 'V'},
				{"ciphers", required_argument, &flag, 1},
				{"groups", required_argument, &flag, 2},
				{"timeout", required_argument, &flag, 3},
				{"preferred-ipv4-addr", required_argument, &flag, 4},
				{"preferred-ipv6-addr", required_argument, &flag, 5},
				{nullptr, 0, nullptr, 0}};

		auto optidx = 0;
		auto c = getopt_long(argc, argv, "d:hqr:st:V", long_opts, &optidx);
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'h':
				// --help
				print_help();
			exit(EXIT_SUCCESS);
			case 'q':
				// -quiet
				svConfig.quiet = true;
				break;
			case 'r':
				// --rx-loss
				svConfig.rx_loss_prob = strtod(optarg, nullptr);
				break;
			case 's':
				// --show-secret
				svConfig.show_secret = true;
				break;
			case 't':
				// --tx-loss
				svConfig.tx_loss_prob = strtod(optarg, nullptr);
				break;
			case 'V':
				// --validate-addr
				svConfig.validate_addr = true;
				break;
			case '?':
				print_usage();
			exit(EXIT_FAILURE);
			case 0:
				switch (flag) {
				case 1:
					// --ciphers
					svConfig.ciphers = optarg;
					break;
				case 2:
					// --groups
					svConfig.groups = optarg;
					break;
				case 3:
					// --timeout
					svConfig.timeout = strtol(optarg, nullptr, 10);
					break;
				case 4:
					// --preferred-ipv4-addr
					if (parse_host_port(svConfig.preferred_ipv4_addr, AF_INET, optarg,
														optarg + strlen(optarg)) != 0) {
					std::cerr << "preferred-ipv4-addr: could not use '" << optarg << "'"
										<< std::endl;
					exit(EXIT_FAILURE);
				}
					break;
				case 5:
					// --preferred-ipv6-addr
					if (parse_host_port(svConfig.preferred_ipv6_addr, AF_INET6, optarg,
														optarg + strlen(optarg)) != 0) {
					std::cerr << "preferred-ipv6-addr: could not use '" << optarg << "'"
										<< std::endl;
					exit(EXIT_FAILURE);
				}
					break;
			}
				break;
			default:
				break;
		};
	}

	if (argc - optind < 4) {
		std::cerr << "Too few arguments" << std::endl;
		print_usage();
		exit(EXIT_FAILURE);
	}

	auto addr = argv[optind++];
	auto port = argv[optind++];
	auto private_key_file = argv[optind++];
	auto cert_file = argv[optind++];

	errno = 0;
	svConfig.port = strtoul(port, nullptr, 10);
	if (errno != 0) {
		std::cerr << "port: invalid port number" << std::endl;
		exit(EXIT_FAILURE);
	}

	auto ssl_ctx = create_ssl_ctx(private_key_file, cert_file);
	if (ssl_ctx == nullptr) {
		exit(EXIT_FAILURE);
	}

	auto ssl_ctx_d = defer(SSL_CTX_free, ssl_ctx);

	auto ev_loop_d = defer(ev_loop_destroy, EV_DEFAULT);

	if (isatty(STDOUT_FILENO)) {
		debug::set_color_output(true);
	}

	auto keylog_filename = getenv("SSLKEYLOGFILE");
	if (keylog_filename) {
		keylog_file.open(keylog_filename, std::ios_base::app);
		if (keylog_file) {
			SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
		}
	}

	Server s(EV_DEFAULT, ssl_ctx);
	if (s.init(addr, port) != 0) {
		exit(EXIT_FAILURE);
	}

	ev_run(EV_DEFAULT, 0);

	s.disconnect();
	s.close();

	return EXIT_SUCCESS;
}
