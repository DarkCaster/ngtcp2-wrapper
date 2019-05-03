#include "server_config.h"
#include "string.h"

void server_config_set_default(struct ServerConfig *config)
{
	memset(config,0,sizeof(struct ServerConfig));
	config->tx_loss_prob = 0.;
	config->rx_loss_prob = 0.;
	config->ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
	config->groups = "P-256:X25519:P-384:P-521";
	config->timeout = 30000;
}
