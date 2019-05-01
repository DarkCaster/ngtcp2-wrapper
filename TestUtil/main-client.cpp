#include "config.h"
#include <getopt.h>
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include "client.h"
#include <netdb.h>
#include <unistd.h>
#include "debug.h"
#include <fstream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "util.h"
#include <fcntl.h>
#include <sys/mman.h>
#include "http_parser.h"
#include <bits/unique_ptr.h>

int write_transport_params(const char *path,
                           const ngtcp2_transport_params *params) {
	auto f = std::ofstream(path);
	if (!f) {
		return -1;
	}

	f << "initial_max_streams_bidi=" << params->initial_max_streams_bidi << "\n"
	  << "initial_max_streams_uni=" << params->initial_max_streams_uni << "\n"
	  << "initial_max_stream_data_bidi_local="
	  << params->initial_max_stream_data_bidi_local << "\n"
	  << "initial_max_stream_data_bidi_remote="
	  << params->initial_max_stream_data_bidi_remote << "\n"
	  << "initial_max_stream_data_uni=" << params->initial_max_stream_data_uni
	  << "\n"
	  << "initial_max_data=" << params->initial_max_data << "\n";

	f.close();
	if (!f) {
		return -1;
	}

	return 0;
}

int transport_params_add_cb(SSL *ssl, unsigned int ext_type,
                            unsigned int content, const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx, int *al,
                            void *add_arg) {
	auto c = static_cast<Client *>(SSL_get_app_data(ssl));
	auto conn = c->conn();

	ngtcp2_transport_params params;

	ngtcp2_conn_get_local_transport_params(conn, &params);

	constexpr size_t bufsize = 64;
	auto buf = std::make_unique<uint8_t[]>(bufsize);

	auto nwrite = ngtcp2_encode_transport_params(
	    buf.get(), bufsize, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
	if (nwrite < 0) {
		std::cerr << "ngtcp2_encode_transport_params: " << ngtcp2_strerror(nwrite)
		          << std::endl;
		*al = SSL_AD_INTERNAL_ERROR;
		return -1;
	}

	*out = buf.release();
	*outlen = static_cast<size_t>(nwrite);

	return 1;
}

void transport_params_free_cb(SSL *ssl, unsigned int ext_type,
                              unsigned int context, const unsigned char *out,
                              void *add_arg) {
	delete[] const_cast<unsigned char *>(out);
}

int transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
                              unsigned int context, const unsigned char *in,
                              size_t inlen, X509 *x, size_t chainidx, int *al,
                              void *parse_arg) {
	auto c = static_cast<Client *>(SSL_get_app_data(ssl));
	auto conn = c->conn();

	int rv;

	ngtcp2_transport_params params;

	rv = ngtcp2_decode_transport_params(
	    &params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, in, inlen);
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

	if (clConfig.tp_file && write_transport_params(clConfig.tp_file, &params) != 0) {
		std::cerr << "Could not write transport parameters in " << clConfig.tp_file
		          << std::endl;
	}

	return 1;
}

int new_session_cb(SSL *ssl, SSL_SESSION *session) {
	if (SSL_SESSION_get_max_early_data(session) !=
	    std::numeric_limits<uint32_t>::max()) {
		std::cerr << "max_early_data_size is not 0xffffffff" << std::endl;
	}
	auto f = BIO_new_file(clConfig.session_file, "w");
	if (f == nullptr) {
		std::cerr << "Could not write TLS session in " << clConfig.session_file
		          << std::endl;
		return 0;
	}

	PEM_write_bio_SSL_SESSION(f, session);
	BIO_free(f);

	return 0;
}

SSL_CTX *create_ssl_ctx() {
	auto ssl_ctx = SSL_CTX_new(TLS_method());

	SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

	// This makes OpenSSL client not send CCS after an initial
	// ClientHello.
	SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

	SSL_CTX_set_default_verify_paths(ssl_ctx);

	if (SSL_CTX_set_ciphersuites(ssl_ctx, clConfig.ciphers) != 1) {
		std::cerr << "SSL_CTX_set_ciphersuites: "
		          << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_set1_groups_list(ssl_ctx, clConfig.groups) != 1) {
		std::cerr << "SSL_CTX_set1_groups_list failed" << std::endl;
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_QUIC_HACK);

	if (SSL_CTX_add_custom_ext(
	        ssl_ctx, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
	        SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
	        transport_params_add_cb, transport_params_free_cb, nullptr,
	        transport_params_parse_cb, nullptr) != 1) {
		std::cerr << "SSL_CTX_add_custom_ext(NGTCP2_TLSEXT_QUIC_TRANSPORT_"
		             "PARAMETERS) failed: "
		          << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
		exit(EXIT_FAILURE);
	}

	if (clConfig.session_file) {
		SSL_CTX_set_session_cache_mode(
		    ssl_ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
		SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);
	}

	return ssl_ctx;
}



std::string get_string(const char *uri, const http_parser_url &u,
                       http_parser_url_fields f) {
	auto p = &u.field_data[f];
	return {uri + p->off, uri + p->off + p->len};
}

int parse_uri(const char *uri) {
	http_parser_url u;

	http_parser_url_init(&u);
	if (http_parser_parse_url(uri, strlen(uri), /* is_connect = */ 0, &u) != 0) {
		return -1;
	}

	if (!(u.field_set & (1 << UF_SCHEMA)) || !(u.field_set & (1 << UF_HOST))) {
		return -1;
	}

	clConfig.scheme = get_string(uri, u, UF_SCHEMA);

	clConfig.authority = get_string(uri, u, UF_HOST);
	if (util::numeric_host(clConfig.authority.c_str())) {
		clConfig.authority = '[' + clConfig.authority + ']';
	}
	if (u.field_set & (1 << UF_PORT)) {
		clConfig.authority += ':';
		clConfig.authority += get_string(uri, u, UF_PORT);
	}

	if (u.field_set & (1 << UF_PATH)) {
		clConfig.path = get_string(uri, u, UF_PATH);
	} else {
		clConfig.path = "/";
	}

	if (u.field_set & (1 << UF_QUERY)) {
		clConfig.path += '?';
		clConfig.path += get_string(uri, u, UF_QUERY);
	}

	return 0;
}

std::ofstream keylog_file;

void keylog_callback(const SSL *ssl, const char *line) {
	keylog_file.write(line, strlen(line));
	keylog_file.put('\n');
	keylog_file.flush();
}

void print_usage() {
	std::cerr << "Usage: client [OPTIONS] <ADDR> <PORT> <URI>" << std::endl;
}

void config_set_default(ClientConfig &config) {
	config = ClientConfig{};
	config.tx_loss_prob = 0.;
	config.rx_loss_prob = 0.;
	config.fd = -1;
	config.ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"
	                 "POLY1305_SHA256";
	config.groups = "P-256:X25519:P-384:P-521";
	config.nstreams = 1;
	config.data = nullptr;
	config.datalen = 0;
	config.version = NGTCP2_PROTO_VER_D19;
	config.timeout = 30000;
	config.http_method = "GET";
}

namespace {
void print_help() {
	print_usage();

	config_set_default(clConfig);

	std::cout << R"(
	<ADDR>      Remote server address
	<PORT>      Remote server port
Options:
	-t, --tx-loss=<P>
	            The probability of losing outgoing packets.  <P> must be
	            [0.0, 1.0],  inclusive.  0.0 means no  packet loss.  1.0
	            means 100% packet loss.
	-r, --rx-loss=<P>
	            The probability of losing incoming packets.  <P> must be
	            [0.0, 1.0],  inclusive.  0.0 means no  packet loss.  1.0
	            means 100% packet loss.
	-d, --data=<PATH>
	            Read data from <PATH>, and send them as STREAM data.
	-n, --nstreams=<N>
	            When used with --data,  this option specifies the number
	            of streams to send the data specified by --data.
	-v, --version=<HEX>
	            Specify QUIC version to use in hex string.
	            Default: )"
	          << std::hex << "0x" << clConfig.version << std::dec << R"(
	-q, --quiet Suppress debug output.
	-s, --show-secret
	            Print out secrets unless --quiet is used.
	--timeout=<T>
	            Specify idle timeout in milliseconds.
	            Default: )"
	          << clConfig.timeout << R"(
	--ciphers=<CIPHERS>
	            Specify the cipher suite list to enable.
	            Default: )"
	          << clConfig.ciphers << R"(
	--groups=<GROUPS>
	            Specify the supported groups.
	            Default: )"
	          << clConfig.groups << R"(
	--session-file=<PATH>
	            Read/write  TLS session  from/to  <PATH>.   To resume  a
	            session, the previous session must be supplied with this
	            option.
	--tp-file=<PATH>
	            Read/write QUIC transport parameters from/to <PATH>.  To
	            send 0-RTT data, the  transport parameters received from
	            the previous session must be supplied with this option.
	--dcid=<DCID>
	            Specify  initial  DCID.   <DCID> is  hex  string.   When
	            decoded as binary, it should be  at least 8 bytes and at
	            most 18 bytes long.
	--change-local-addr=<T>
	            Client  changes local  address when  <T> seconds  elapse
	            after handshake completes.
	--nat-rebinding
	            When   used  with   --change-local-addr,  simulate   NAT
	            rebinding.   In   other  words,  client   changes  local
	            address, but it does not start path validation.
	--key-update=<T>
	            Client  initiates key  update  when  <T> seconds  elapse
	            after handshake completes.
	-m, --http-method=<METHOD>
	            Specify HTTP method.  Default: )"
	          << clConfig.http_method << R"(
	--delay-stream=<T>
	            Delay sending STREAM data in 1-RTT for <T> seconds after
	            handshake completes.
	--no-preferred-addr
	            Do not try to use preferred address offered by server.
	-h, --help  Display this help and exit.
)";
}
} // namespace

int main(int argc, char **argv) {
	config_set_default(clConfig);
	char *data_path = nullptr;

	for (;;) {
		static int flag = 0;
		constexpr static option long_opts[] = {
		    {"help", no_argument, nullptr, 'h'},
		    {"tx-loss", required_argument, nullptr, 't'},
		    {"rx-loss", required_argument, nullptr, 'r'},
		    {"data", required_argument, nullptr, 'd'},
		    {"http-method", required_argument, nullptr, 'm'},
		    {"nstreams", required_argument, nullptr, 'n'},
		    {"version", required_argument, nullptr, 'v'},
		    {"quiet", no_argument, nullptr, 'q'},
		    {"show-secret", no_argument, nullptr, 's'},
		    {"ciphers", required_argument, &flag, 1},
		    {"groups", required_argument, &flag, 2},
		    {"timeout", required_argument, &flag, 3},
		    {"session-file", required_argument, &flag, 4},
		    {"tp-file", required_argument, &flag, 5},
		    {"dcid", required_argument, &flag, 6},
		    {"change-local-addr", required_argument, &flag, 7},
		    {"key-update", required_argument, &flag, 8},
		    {"nat-rebinding", no_argument, &flag, 9},
		    {"delay-stream", required_argument, &flag, 10},
		    {"no-preferred-addr", no_argument, &flag, 11},
		    {nullptr, 0, nullptr, 0},
		};

		auto optidx = 0;
		auto c = getopt_long(argc, argv, "d:him:n:qr:st:v:", long_opts, &optidx);
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'd':
				// --data
				data_path = optarg;
				break;
			case 'h':
				// --help
				print_help();
			exit(EXIT_SUCCESS);
			case 'm':
				// --http-method
				clConfig.http_method = optarg;
				break;
			case 'n':
				// --streams
				clConfig.nstreams = strtol(optarg, nullptr, 10);
				break;
			case 'q':
				// -quiet
				clConfig.quiet = true;
				break;
			case 'r':
				// --rx-loss
				clConfig.rx_loss_prob = strtod(optarg, nullptr);
				break;
			case 's':
				// --show-secret
				clConfig.show_secret = true;
				break;
			case 't':
				// --tx-loss
				clConfig.tx_loss_prob = strtod(optarg, nullptr);
				break;
			case 'v':
				// --version
				clConfig.version = strtol(optarg, nullptr, 16);
				break;
			case '?':
				print_usage();
			exit(EXIT_FAILURE);
			case 0:
				switch (flag) {
				case 1:
					// --ciphers
					clConfig.ciphers = optarg;
					break;
				case 2:
					// --groups
					clConfig.groups = optarg;
					break;
				case 3:
					// --timeout
					clConfig.timeout = strtol(optarg, nullptr, 10);
					break;
				case 4:
					// --session-file
					clConfig.session_file = optarg;
					break;
				case 5:
					// --tp-file
					clConfig.tp_file = optarg;
					break;
				case 6: {
					// --dcid
					auto dcidlen2 = strlen(optarg);
				if (dcidlen2 % 2 || dcidlen2 / 2 < 8 || dcidlen2 / 2 > 18) {
					std::cerr << "dcid: wrong length" << std::endl;
					exit(EXIT_FAILURE);
				}
				auto dcid = util::decode_hex(optarg);
				ngtcp2_cid_init(&clConfig.dcid,
				                reinterpret_cast<const uint8_t *>(dcid.c_str()),
				                dcid.size());
				break;
				}
				case 7:
					// --change-local-addr
					clConfig.change_local_addr = strtod(optarg, nullptr);
					break;
				case 8:
					// --key-update
					clConfig.key_update = strtod(optarg, nullptr);
					break;
				case 9:
					// --nat-rebinding
					clConfig.nat_rebinding = true;
					break;
				case 10:
					// --delay-stream
					clConfig.delay_stream = strtod(optarg, nullptr);
					break;
				case 11:
					// --no-preferred-addr
					clConfig.no_preferred_addr = true;
					break;
			}
				break;
			default:
				break;
		};
	}

	if (argc - optind < 3) {
		std::cerr << "Too few arguments" << std::endl;
		print_usage();
		exit(EXIT_FAILURE);
	}

	if (data_path) {
		auto fd = open(data_path, O_RDONLY);
		if (fd == -1) {
			std::cerr << "data: Could not open file " << data_path << ": "
			          << strerror(errno) << std::endl;
			exit(EXIT_FAILURE);
		}
		struct stat st;
		if (fstat(fd, &st) != 0) {
			std::cerr << "data: Could not stat file " << data_path << ": "
			          << strerror(errno) << std::endl;
			exit(EXIT_FAILURE);
		}
		clConfig.fd = fd;
		clConfig.datalen = st.st_size;
		clConfig.data = static_cast<uint8_t *>(
		    mmap(nullptr, clConfig.datalen, PROT_READ, MAP_SHARED, fd, 0));
	}

	auto addr = argv[optind++];
	auto port = argv[optind++];
	auto uri = argv[optind++];

	if (parse_uri(uri) != 0) {
		std::cerr << "Could not parse URI " << uri << std::endl;
		exit(EXIT_FAILURE);
	}

	auto ssl_ctx = create_ssl_ctx();
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

	Client c(EV_DEFAULT, ssl_ctx);

	if (run(c, addr, port) != 0) {
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

