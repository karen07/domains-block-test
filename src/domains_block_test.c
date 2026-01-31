#include "domains_block_test.h"

uint32_t rps;
double one_cycle_ns;
volatile double coeff = 1;

volatile int32_t keep_sending = 1;
volatile int32_t keep_reading = 1;

volatile int32_t syn_sended;
volatile int32_t tls_sended;
volatile int32_t tls_error_readed;

pcap_t *handle;

unsigned char dev_mac[ETH_ALEN];
unsigned char gateway_mac[ETH_ALEN];
uint32_t dev_ip;

array_hashmap_t ip_map_struct;

int32_t domains_count = 0;
domain_status_t *domains = NULL;

int32_t domains_index = 0;

int32_t IPs_count = 0;
uint32_t *IPs = NULL;

int32_t try_count = 0;

volatile time_t now_for_del;

void errmsg(const char *format, ...)
{
    va_list args;

    printf("Error: ");

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    exit(EXIT_FAILURE);
}

int32_t tls_client_hello(char *send_data, char *sni)
{
    int32_t sni_len = strlen(sni);

    tls_data_t *buff;
    buff = (tls_data_t *)send_data;

    buff->content_type = 22;
    buff->tls_version = htons(0x0301);
    buff->tls_length = htons(sizeof(tls_data_t) + sni_len - 5);

    buff->handshake_type = 1;
    buff->handshake_length_1 = 0;
    buff->handshake_length_2 = htons(sizeof(tls_data_t) + sni_len - 5 - 4);
    buff->handshake_version = htons(0x0303);

    for (int32_t i = 0; i < (int32_t)sizeof(buff->random); i++) {
        buff->random[i] = rand();
    }

    buff->session_id_length = 32;
    for (int32_t i = 0; i < (int32_t)sizeof(buff->session_id); i++) {
        buff->session_id[i] = rand();
    }

    buff->cipher_suites_length = htons(2);
    buff->cipher_suites = htons(0x1302);

    buff->compression_methods_length = 1;
    buff->compression_methods = 0;

    buff->extensions_length = htons(9 + sni_len);

    buff->extensions_type = htons(0);
    buff->extension_length = htons(5 + sni_len);

    buff->sni_list_length = htons(3 + sni_len);
    buff->sni_type = 0;
    buff->sni_length = htons(sni_len);

    strcpy(send_data + sizeof(tls_data_t), sni);

    return sizeof(tls_data_t) + sni_len;
}

uint32_t djb33_hash_len(const char *s, size_t len)
{
    uint32_t h = 5381;
    while (*s && len--) {
        h += (h << 5);
        h ^= *s++;
    }
    return h;
}

static array_hashmap_hash ip_add_hash(const void *add_elem_data)
{
    const conn_data_t *elem = add_elem_data;
    return djb33_hash_len((char *)&elem->IP, sizeof(elem->IP) + sizeof(elem->port));
}

static array_hashmap_bool ip_add_cmp(const void *add_elem_data, const void *hashmap_elem_data)
{
    const conn_data_t *elem1 = add_elem_data;
    const conn_data_t *elem2 = hashmap_elem_data;

    return ((elem1->IP == elem2->IP) && (elem1->port == elem2->port));
}

static uint16_t checksum(char *buf, uint32_t size)
{
    uint32_t sum = 0, i;

    for (i = 0; i < size - 1; i += 2) {
        uint16_t word16 = *(uint16_t *)&buf[i];
        sum += word16;
    }

    if (size & 1) {
        uint16_t word16 = (uint8_t)buf[i];
        sum += word16;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

static void tcp_checksum(struct iphdr *iph)
{
    struct tcphdr *tcph = (struct tcphdr *)((char *)iph + sizeof(*iph));

    uint16_t L4_len = ntohs(iph->tot_len) - (iph->ihl << 2);

    pseudo_header_t psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.protocol = htons(IPPROTO_TCP);
    psh.length = htons(L4_len);

    char pseudogram[PACKET_MAX_SIZE];
    memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header_t));
    memcpy(pseudogram + sizeof(pseudo_header_t), tcph, L4_len);

    int32_t psize = sizeof(pseudo_header_t) + L4_len;
    uint16_t checksum_value = checksum(pseudogram, psize);

    tcph->check = checksum_value;
    iph->check = checksum((char *)iph, iph->ihl << 2);
}

void *read_raw(void *arg)
{
    (void)arg;

    while (keep_reading) {
        struct pcap_pkthdr read_header;
        memset(&read_header, 0, sizeof(struct pcap_pkthdr));

        const u_char *read_data;
        read_data = pcap_next(handle, &read_header);
        if (read_header.len < ETH_IP_TCP_S) {
            continue;
        }

        struct ethhdr *eth_h_read = (struct ethhdr *)read_data;
        if (eth_h_read->h_proto != htons(ETH_P_IP)) {
            continue;
        }

        struct iphdr *iph_read = (struct iphdr *)((char *)eth_h_read + sizeof(*eth_h_read));
        if (iph_read->protocol != IPPROTO_TCP) {
            continue;
        }

        struct tcphdr *tcph_read = (struct tcphdr *)((char *)iph_read + sizeof(*iph_read));
        if (tcph_read->source != htons(PORT_TLS)) {
            continue;
        }

        conn_data_t find_elem;
        find_elem.IP = iph_read->saddr;
        find_elem.port = tcph_read->dest;

        conn_data_t res_elem;

        int32_t find_res;
        find_res = array_hashmap_find_elem(ip_map_struct, &find_elem, &res_elem);
        if (find_res != array_hashmap_elem_finded) {
            continue;
        }

        if (res_elem.status == TLS_SENDED) {
            if (ntohs(iph_read->tot_len) == 47) {
                char *tls = (char *)tcph_read + sizeof(*tcph_read);
                if ((tls[0] == 0x15) && (tls[1] == 0x3)) {
                    tls_error_readed++;

                    res_elem.domain->status++;

                    int32_t array_hashmap_ret;
                    array_hashmap_ret = array_hashmap_del_elem(ip_map_struct, &res_elem, NULL);
                    if (array_hashmap_ret != array_hashmap_elem_deled) {
                        errmsg("array_hashmap_elem_not_deled\n");
                    }

                    /*struct iphdr *iph_send = (struct iphdr *)write_data_ack;
                    iph_send->version = 4;
                    iph_send->ihl = sizeof(struct iphdr) / 4;
                    iph_send->tos = 0;
                    iph_send->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                    iph_send->id = 0;
                    iph_send->frag_off = htons(0x4000);
                    iph_send->ttl = 128;
                    iph_send->protocol = IPPROTO_TCP;
                    iph_send->check = 0;
                    iph_send->saddr = iph_read->daddr;
                    iph_send->daddr = iph_read->saddr;

                    struct tcphdr *tcph_send =
                        (struct tcphdr *)(write_data_ack + sizeof(struct iphdr));
                    tcph_send->source = tcph_read->dest;
                    tcph_send->dest = tcph_read->source;
                    tcph_send->seq = tcph_read->ack_seq;
                    tcph_send->ack_seq = htonl(ntohl(tcph_read->seq) + 1);
                    tcph_send->res1 = 0;
                    tcph_send->doff = (sizeof(struct tcphdr)) / 4;
                    tcph_send->ack = 1;
                    tcph_send->rst = 1;
                    tcph_send->window = 0xffff;
                    tcph_send->check = 0;
                    tcph_send->urg_ptr = 0;*/
                }
            }
        }

        if ((res_elem.status == SYN_SENDED) && keep_sending) {
            if ((tcph_read->syn == 1) && (tcph_read->ack == 1)) {
                {
                    char write_data_ack[ETH_IP_TCP_S];
                    memset(write_data_ack, 0, ETH_IP_TCP_S);

                    struct ethhdr *eth_h_send = (struct ethhdr *)write_data_ack;
                    eth_h_send->h_proto = htons(ETH_P_IP);
                    memcpy(&eth_h_send->h_dest, gateway_mac, ETH_ALEN);
                    memcpy(&eth_h_send->h_source, dev_mac, ETH_ALEN);

                    struct iphdr *iph_send =
                        (struct iphdr *)((char *)eth_h_send + sizeof(*eth_h_send));
                    iph_send->version = 4;
                    iph_send->ihl = sizeof(struct iphdr) / 4;
                    iph_send->tos = 0;
                    iph_send->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                    iph_send->id = 0;
                    iph_send->frag_off = htons(0x4000);
                    iph_send->ttl = 128;
                    iph_send->protocol = IPPROTO_TCP;
                    iph_send->check = 0;
                    iph_send->saddr = iph_read->daddr;
                    iph_send->daddr = iph_read->saddr;

                    struct tcphdr *tcph_send =
                        (struct tcphdr *)((char *)iph_send + sizeof(*iph_send));
                    tcph_send->source = tcph_read->dest;
                    tcph_send->dest = tcph_read->source;
                    tcph_send->seq = tcph_read->ack_seq;
                    tcph_send->ack_seq = htonl(ntohl(tcph_read->seq) + 1);
                    tcph_send->res1 = 0;
                    tcph_send->doff = (sizeof(struct tcphdr)) / 4;
                    tcph_send->ack = 1;
                    tcph_send->window = 0xffff;
                    tcph_send->check = 0;
                    tcph_send->urg_ptr = 0;

                    tcp_checksum(iph_send);

                    pcap_inject(handle, write_data_ack, ETH_IP_TCP_S);
                }

                {
                    char write_data[PACKET_MAX_SIZE];
                    memset(write_data, 0, PACKET_MAX_SIZE);

                    struct ethhdr *eth_h_send = (struct ethhdr *)write_data;
                    eth_h_send->h_proto = htons(ETH_P_IP);
                    memcpy(&eth_h_send->h_dest, gateway_mac, ETH_ALEN);
                    memcpy(&eth_h_send->h_source, dev_mac, ETH_ALEN);

                    struct iphdr *iph_send =
                        (struct iphdr *)((char *)eth_h_send + sizeof(*eth_h_send));
                    iph_send->version = 4;
                    iph_send->ihl = sizeof(struct iphdr) / 4;
                    iph_send->tos = 0;
                    iph_send->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                    iph_send->id = 0;
                    iph_send->frag_off = htons(0x4000);
                    iph_send->ttl = 128;
                    iph_send->protocol = IPPROTO_TCP;
                    iph_send->check = 0;
                    iph_send->saddr = iph_read->daddr;
                    iph_send->daddr = iph_read->saddr;

                    struct tcphdr *tcph_send =
                        (struct tcphdr *)((char *)iph_send + sizeof(*iph_send));
                    tcph_send->source = tcph_read->dest;
                    tcph_send->dest = tcph_read->source;
                    tcph_send->seq = tcph_read->ack_seq;
                    tcph_send->ack_seq = htonl(ntohl(tcph_read->seq) + 1);
                    tcph_send->res1 = 0;
                    tcph_send->doff = (sizeof(struct tcphdr)) / 4;
                    tcph_send->ack = 1;
                    tcph_send->psh = 1;
                    tcph_send->window = 0xffff;
                    tcph_send->check = 0;
                    tcph_send->urg_ptr = 0;

                    char *tls_send = (char *)tcph_send + sizeof(*tcph_send);
                    int32_t tls_send_size = 0;
                    tls_send_size = tls_client_hello(tls_send, domains[domains_index].domain);

                    res_elem.domain = &domains[domains_index];
                    res_elem.status = TLS_SENDED;
                    res_elem.time = time(NULL);

                    int32_t array_hashmap_ret;
                    array_hashmap_ret = array_hashmap_add_elem(ip_map_struct, &res_elem, NULL,
                                                               array_hashmap_save_new_func);
                    if (array_hashmap_ret != array_hashmap_elem_already_in) {
                        errmsg("array_hashmap_elem_not_already_in\n");
                    }

                    domains_index++;
                    if (!(domains_index < domains_count)) {
                        domains_index = 0;
                        try_count++;
                    }
                    if (!(try_count < TRY_COUNT)) {
                        keep_sending = 0;
                    }

                    iph_send->tot_len =
                        htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + tls_send_size);

                    tcp_checksum(iph_send);

                    pcap_inject(handle, write_data, ETH_IP_TCP_S + tls_send_size);
                    tls_sended++;
                }
            }
        }
    }

    return NULL;
}

void *send_raw(void *arg)
{
    (void)arg;

    const int32_t all_size = ETH_IP_TCP_S + sizeof(tcp_mss_opt_t);

    char write_data[all_size];

    while (keep_sending) {
        conn_data_t add_elem;

        while (true) {
            add_elem.IP = IPs[rand() % IPs_count];
            add_elem.port = rand();
            add_elem.status = SYN_SENDED;
            add_elem.time = time(NULL);
            add_elem.domain = NULL;

            array_hashmap_ret_t ret;
            ret =
                array_hashmap_add_elem(ip_map_struct, &add_elem, NULL, array_hashmap_save_old_func);
            if (ret == array_hashmap_elem_added) {
                break;
            }
            if (ret == array_hashmap_full) {
                errmsg("array_hashmap_full\n");
            }
        }

        memset(write_data, 0, all_size);

        struct ethhdr *eth_h = (struct ethhdr *)write_data;
        eth_h->h_proto = htons(ETH_P_IP);
        memcpy(&eth_h->h_dest, gateway_mac, ETH_ALEN);
        memcpy(&eth_h->h_source, dev_mac, ETH_ALEN);

        struct iphdr *iph = (struct iphdr *)((char *)eth_h + sizeof(*eth_h));
        iph->version = 4;
        iph->ihl = sizeof(struct iphdr) / 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(tcp_mss_opt_t));
        iph->id = 0;
        iph->frag_off = htons(0x4000);
        iph->ttl = 128;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = dev_ip;
        iph->daddr = add_elem.IP;

        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + sizeof(*iph));
        tcph->source = add_elem.port;
        tcph->dest = htons(PORT_TLS);
        tcph->seq = rand();
        tcph->ack_seq = 0;
        tcph->res1 = 0;
        tcph->doff = (sizeof(struct tcphdr) + sizeof(tcp_mss_opt_t)) / 4;
        tcph->syn = 1;
        tcph->window = 0xffff;
        tcph->check = 0;
        tcph->urg_ptr = 0;

        tcp_mss_opt_t *tcp_opt_ptr = (tcp_mss_opt_t *)((char *)tcph + sizeof(*tcph));
        tcp_opt_ptr->type = TCP_MAXSEG;
        tcp_opt_ptr->len = sizeof(tcp_mss_opt_t);
        tcp_opt_ptr->mss = htons(1400);

        tcp_checksum(iph);

        pcap_inject(handle, write_data, all_size);
        syn_sended++;

        volatile double time_test = 1.0;
        for (int32_t i = 0; i < 1000000000.0 / rps / one_cycle_ns / coeff; i++) {
            time_test *= 3.0;
        }
    }

    return NULL;
}

static void eth_bin2str(unsigned char *src, char *dst)
{
    sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned int)src[0], (unsigned int)src[1],
            (unsigned int)src[2], (unsigned int)src[3], (unsigned int)src[4], (unsigned int)src[5]);
}

array_hashmap_bool domain_del_func(const void *del_elem_data)
{
    const conn_data_t *elem = del_elem_data;

    if ((now_for_del - elem->time) > TCP_CONN_LIVETIME) {
        return array_hashmap_del_by_func;
    } else {
        return array_hashmap_not_del_by_func;
    }
}

void print_help(void)
{
    printf("Commands:\n"
           "  Required parameters:\n"
           "    -d  \"/test.txt\"  Domains file path\n"
           "    -i  \"/test.txt\"  IPs file path\n"
           "    -n  \"test\"       Dev name\n"
           "    -r  \"xxx\"        Request per second\n");
}

static void main_catch_function(int32_t signo)
{
    if (signo == SIGINT) {
        errmsg("SIGINT catched main\n");
    } else if (signo == SIGSEGV) {
        errmsg("SIGSEGV catched main\n");
    } else if (signo == SIGTERM) {
        errmsg("SIGTERM catched main\n");
    }
}

int32_t main(int32_t argc, char *argv[])
{
    printf("Domains block test started\n\n");

    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGINT signal handler main\n");
    }

    if (signal(SIGSEGV, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGSEGV signal handler main\n");
    }

    if (signal(SIGTERM, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGTERM signal handler main\n");
    }

    //Timer based on for
    {
        struct timeval now_timeval_start;
        gettimeofday(&now_timeval_start, NULL);
        volatile double time_test = 1.0;
        for (int32_t j = 0; j < 1000; j++) {
            for (int32_t i = 0; i < 1000; i++) {
                time_test *= 3.0;
            }
        }
        struct timeval now_timeval_end;
        gettimeofday(&now_timeval_end, NULL);
        uint64_t now_us_start = now_timeval_start.tv_sec * 1000000 + now_timeval_start.tv_usec;
        uint64_t now_us_end = now_timeval_end.tv_sec * 1000000 + now_timeval_end.tv_usec;
        one_cycle_ns = ((now_us_end - now_us_start) * 1000.0) / 1000.0 / 1000.0;
    }
    //Timer based on for

    char domains_file_path[PATH_MAX];
    memset(domains_file_path, 0, PATH_MAX);

    char IPs_file_path[PATH_MAX];
    memset(IPs_file_path, 0, PATH_MAX);

    char dev_name[IFNAMSIZ];
    memset(dev_name, 0, IFNAMSIZ);

    //Args
    {
        printf("Launch parameters:\n");
        for (int32_t i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "-d")) {
                if (i != argc - 1) {
                    printf("  Domains  \"%s\"\n", argv[i + 1]);
                    if (strlen(argv[i + 1]) < PATH_MAX) {
                        strcpy(domains_file_path, argv[i + 1]);
                    }
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "-i")) {
                if (i != argc - 1) {
                    printf("  IPs      \"%s\"\n", argv[i + 1]);
                    if (strlen(argv[i + 1]) < PATH_MAX) {
                        strcpy(IPs_file_path, argv[i + 1]);
                    }
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "-n")) {
                if (i != argc - 1) {
                    printf("  Name     \"%s\"\n", argv[i + 1]);
                    strcpy(dev_name, argv[i + 1]);
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "-r")) {
                if (i != argc - 1) {
                    printf("  RPS      \"%s\"\n", argv[i + 1]);
                    sscanf(argv[i + 1], "%u", &rps);
                    i++;
                }
                continue;
            }
            print_help();
            errmsg("Unknown command %s\n", argv[i]);
        }

        if (domains_file_path[0] == 0) {
            print_help();
            errmsg("Programm need domains file path\n");
        }

        if (IPs_file_path[0] == 0) {
            print_help();
            errmsg("Programm need IPs file path\n");
        }

        if (dev_name[0] == 0) {
            print_help();
            errmsg("Programm need dev name\n");
        }

        if (rps == 0) {
            print_help();
            errmsg("Programm need RPS\n");
        }
    }
    //Args

    printf("\n");

    //Domains read
    {
        FILE *domains_fp = fopen(domains_file_path, "r");
        if (!domains_fp) {
            errmsg("Can't open file %s\n", domains_file_path);
        }

        fseek(domains_fp, 0, SEEK_END);
        int64_t domains_file_size_add = ftell(domains_fp);
        fseek(domains_fp, 0, SEEK_SET);

        char *domains_file_data = (char *)malloc(domains_file_size_add);

        if (fread(domains_file_data, sizeof(char), domains_file_size_add, domains_fp) !=
            (size_t)domains_file_size_add) {
            errmsg("Can't read domains file %s\n", domains_file_path);
        }

        for (int32_t i = 0; i < (int32_t)domains_file_size_add; i++) {
            if (domains_file_data[i] == '\n') {
                domains_file_data[i] = 0;
                domains_count++;
            }
        }

        domains = (domain_status_t *)malloc(domains_count * sizeof(domain_status_t));
        memset(domains, 0, domains_count * sizeof(domain_status_t));

        char *domain_start = domains_file_data;
        for (int32_t i = 0; i < domains_count; i++) {
            domains[i].domain = domain_start;

            domain_start = strchr(domain_start, 0) + 1;
        }

        fclose(domains_fp);

        printf("Domains count: %d\n", domains_count);
    }
    //Domains read

    // HashMap init
    {
        ip_map_struct = array_hashmap_init(rps * 10, 1.0, sizeof(conn_data_t));
        if (ip_map_struct == NULL) {
            errmsg("No free memory for ip_map_struct\n");
        }

        array_hashmap_set_func(ip_map_struct, ip_add_hash, ip_add_cmp, ip_add_hash, ip_add_cmp,
                               ip_add_hash, ip_add_cmp);
    }
    // HashMap init

    //IPs read
    {
        FILE *IPs_fp = fopen(IPs_file_path, "r");
        if (!IPs_fp) {
            errmsg("Can't open file %s\n", IPs_file_path);
        }

        fseek(IPs_fp, 0, SEEK_END);
        int64_t IPs_file_size_add = ftell(IPs_fp);
        fseek(IPs_fp, 0, SEEK_SET);

        char *IPs_file_data = (char *)malloc(IPs_file_size_add);

        if (fread(IPs_file_data, sizeof(char), IPs_file_size_add, IPs_fp) !=
            (size_t)IPs_file_size_add) {
            errmsg("Can't read IPs file %s\n", IPs_file_path);
        }

        for (int32_t i = 0; i < (int32_t)IPs_file_size_add; i++) {
            if (IPs_file_data[i] == '\n') {
                IPs_file_data[i] = 0;
                IPs_count++;
            }
        }

        IPs = (uint32_t *)malloc(IPs_count * sizeof(uint32_t));
        memset(IPs, 0, IPs_count * sizeof(uint32_t));

        char *IP_start = IPs_file_data;
        for (int32_t i = 0; i < IPs_count; i++) {
            IPs[i] = inet_addr(IP_start);

            IP_start = strchr(IP_start, 0) + 1;
        }

        free(IPs_file_data);

        fclose(IPs_fp);

        printf("IPs     count: %d\n", IPs_count);
    }
    //IPs read

    //Open socket
    {
        char errbuf[PCAP_ERRBUF_SIZE];

        handle = pcap_open_live(dev_name, BUFSIZ, 0, 1, errbuf);
        if (handle == NULL) {
            errmsg("Can't open device %s: %s\n", dev_name, errbuf);
        }

        struct ifreq ifreq;
        memset(&ifreq, 0, sizeof(ifreq));
        strcpy(ifreq.ifr_name, dev_name);

        int32_t raw_fd;
        raw_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (raw_fd < 0) {
            errmsg("Can't open a raw socket ETH_P_ALL\n");
        }

        int32_t ret;
        ret = ioctl(raw_fd, SIOCGIFHWADDR, &ifreq);
        if (ret < 0) {
            errmsg("Can't get mac address of interface %s\n", dev_name);
        }
        memcpy(dev_mac, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

        memset(&ifreq, 0, sizeof(ifreq));
        strcpy(ifreq.ifr_name, dev_name);

        ret = ioctl(raw_fd, SIOCGIFADDR, &ifreq);
        if (ret < 0) {
            errmsg("Can't get ip address of interface %s\n", dev_name);
        }
        struct sockaddr_in sin;
        memcpy(&sin, &ifreq.ifr_addr, sizeof(struct sockaddr));
        dev_ip = sin.sin_addr.s_addr;
    }
    //Open socket

    //Find gateway mac
    {
        struct pcap_pkthdr header;
        memset(&header, 0, sizeof(struct pcap_pkthdr));

        const u_char *packet;

        while (true) {
            packet = pcap_next(handle, &header);

            if (header.len < (int32_t)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
                continue;
            }

            struct ethhdr *eth_h = (struct ethhdr *)packet;

            if (eth_h->h_proto != htons(ETH_P_IP)) {
                continue;
            }

            char src[ETH_STRLEN + 1];
            eth_bin2str(eth_h->h_source, src);

            char dst[ETH_STRLEN + 1];
            eth_bin2str(eth_h->h_dest, dst);

            if (memcmp(dev_mac, eth_h->h_source, ETH_ALEN)) {
                memcpy(gateway_mac, eth_h->h_source, ETH_ALEN);
                break;
            }

            if (memcmp(dev_mac, eth_h->h_dest, ETH_ALEN)) {
                memcpy(gateway_mac, eth_h->h_dest, ETH_ALEN);
                break;
            }
        }
    }
    //Find gateway mac

    //Print mac and ip
    {
        char dev_src[ETH_STRLEN + 1];
        eth_bin2str(dev_mac, dev_src);
        printf("Dev       mac: %s\n", dev_src);

        char gateway_src[ETH_STRLEN + 1];
        eth_bin2str(gateway_mac, gateway_src);
        printf("Gateway   mac: %s\n", gateway_src);

        struct in_addr src_ip_s;
        src_ip_s.s_addr = dev_ip;
        printf("Dev        ip: %s\n", inet_ntoa(src_ip_s));
    }
    //Print mac and ip

    //Threads
    {
        pthread_t send_thread;
        if (pthread_create(&send_thread, NULL, send_raw, NULL)) {
            errmsg("Can't create send_thread\n");
        }

        if (pthread_detach(send_thread)) {
            errmsg("Can't detach send_thread\n");
        }

        pthread_t read_thread;
        if (pthread_create(&read_thread, NULL, read_raw, NULL)) {
            errmsg("Can't create read_thread\n");
        }

        if (pthread_detach(read_thread)) {
            errmsg("Can't detach read_thread\n");
        }
    }
    //Threads

    //Stat
    {
        int32_t syn_sended_old = 0;
        int32_t tls_sended_old = 0;
        int32_t tls_error_readed_old = 0;

        int32_t exit_wait = 0;

        struct timeval now_timeval_start;
        struct timeval now_timeval_end;

        memset(&now_timeval_start, 0, sizeof(now_timeval_start));

        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        printf("\nStart time %02d.%02d.%04d %02d:%02d:%02d\n\n", tm_struct->tm_mday,
               tm_struct->tm_mon + 1, tm_struct->tm_year + 1900, tm_struct->tm_hour,
               tm_struct->tm_min, tm_struct->tm_sec);

        char print_format[100];
        char *print_data[100];
        print_data[0] = "Try;";
        print_data[1] = " Send_SYN_RPS;";
        print_data[2] = " Send_TLS_RPS;";
        print_data[3] = " Read_TLS_RPS;";
        print_data[4] = "   Sended_SYN;";
        print_data[5] = "   Sended_TLS;";
        print_data[6] = "   Readed_TLS;";

        for (int32_t i = 0; i < 7; i++) {
            printf("%s", print_data[i]);
        }
        printf("\n");

        while (true) {
            sleep(1);

            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[0]) - 1));
            printf(print_format, try_count);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[1]) - 1));
            printf(print_format, syn_sended - syn_sended_old);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[2]) - 1));
            printf(print_format, tls_sended - tls_sended_old);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[3]) - 1));
            printf(print_format, tls_error_readed - tls_error_readed_old);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[4]) - 1));
            printf(print_format, syn_sended);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[5]) - 1));
            printf(print_format, tls_sended);
            sprintf(print_format, "%%%dd;", (int32_t)(strlen(print_data[6]) - 1));
            printf(print_format, tls_error_readed);
            printf("\n");
            fflush(stdout);

            if ((tls_error_readed - tls_error_readed_old) < EXIT_WAIT_DIFF) {
                exit_wait++;
            } else {
                exit_wait = 0;
            }

            if (exit_wait >= EXIT_WAIT_SEC) {
                break;
            }

            gettimeofday(&now_timeval_end, NULL);

            if (now_timeval_start.tv_sec != 0) {
                uint64_t now_us_start =
                    now_timeval_start.tv_sec * 1000000 + now_timeval_start.tv_usec;
                uint64_t now_us_end = now_timeval_end.tv_sec * 1000000 + now_timeval_end.tv_usec;
                double real_rps =
                    (tls_sended - tls_sended_old) / ((now_us_end - now_us_start) / 1000000.0);
                coeff *= rps / real_rps;
            }

            gettimeofday(&now_timeval_start, NULL);

            syn_sended_old = syn_sended;
            tls_sended_old = tls_sended;
            tls_error_readed_old = tls_error_readed;

            now_for_del = time(NULL);
            array_hashmap_del_elem_by_func(ip_map_struct, domain_del_func);
        }

        keep_reading = 0;

        sleep(1);

        now = time(NULL);
        tm_struct = localtime(&now);
        printf("\nEnd time %02d.%02d.%04d %02d:%02d:%02d\n", tm_struct->tm_mday,
               tm_struct->tm_mon + 1, tm_struct->tm_year + 1900, tm_struct->tm_hour,
               tm_struct->tm_min, tm_struct->tm_sec);
        fflush(stdout);
    }
    //Stat

    //Write blocked
    {
        FILE *blocked_fp = fopen("blocked.txt", "w");
        if (!blocked_fp) {
            errmsg("Can't open file blocked.txt\n");
        }

        for (int32_t i = 0; i < domains_count; i++) {
            if (domains[i].status < TRY_COUNT / 6) {
                fprintf(blocked_fp, "%d %s\n", domains[i].status, domains[i].domain);
            }
        }

        fclose(blocked_fp);
    }
    //Write blocked

    //Free
    {
        pcap_close(handle);

        free(domains);

        free(IPs);

        array_hashmap_del(&ip_map_struct);
    }
    //Free

    return EXIT_SUCCESS;
}
