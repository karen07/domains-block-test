#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/route.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include "array_hashmap.h"

#define PORT_TLS 443
#define PACKET_MAX_SIZE 1500
#define TRY_COUNT 30
#define EXIT_WAIT_SEC 5
#define TCP_CONN_LIVETIME 5
#define EXIT_WAIT_DIFF 10

#define SYN_SENDED 1
#define TLS_SENDED 2

#define ETH_IP_TCP_S \
    ((int32_t)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))

#define STRLEN(s) ((sizeof(s) / sizeof(s[0])) - 1)
#define ETH_STRLEN STRLEN("00:11:22:33:44:55")

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

typedef struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint16_t protocol;
    uint16_t length;
} __attribute__((packed)) pseudo_header_t;

typedef struct tcp_mss_opt {
    char type;
    char len;
    uint16_t mss;
} __attribute__((packed)) tcp_mss_opt_t;

typedef struct domain_status {
    char *domain;
    uint8_t status;
} __attribute__((packed)) domain_status_t;

typedef struct conn_data {
    time_t time;
    domain_status_t *domain;
    uint32_t IP;
    uint16_t port;
    uint8_t status;
} __attribute__((packed)) conn_data_t;
