#include <linux/limits.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#define PORT_TLS 443
#define PACKET_MAX_SIZE 1500
#define MAX_SOCKET_COUNT 1000
#define POLL_SLEEP_TIME 1000
#define TRY_COUNT 10

typedef struct tls_data {
    uint8_t content_type;
    uint16_t tls_version;
    uint16_t tls_length;

    uint8_t handshake_type;
    uint8_t handshake_length_1;
    uint16_t handshake_length_2;
    uint16_t handshake_version;

    uint8_t random[32];

    uint8_t session_id_length;
    uint8_t session_id[32];

    uint16_t cipher_suites_length;
    uint16_t cipher_suites;

    uint8_t compression_methods_length;
    uint8_t compression_methods;

    uint16_t extensions_length;

    uint16_t extensions_type;
    uint16_t extension_length;

    uint16_t sni_list_length;
    uint8_t sni_type;
    uint16_t sni_length;
} __attribute__((packed)) tls_data_t;
