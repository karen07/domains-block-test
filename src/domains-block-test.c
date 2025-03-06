#include "domains-block-test.h"

uint32_t rps;
double coeff = 1;

volatile int32_t keep_sending = 1;

volatile int32_t sended;
volatile int32_t readed;

int32_t raw_fd = 0;
uint32_t dev_ip = 0;

array_hashmap_t ip_map_struct;

int32_t domains_count = 0;
domain_status_t *domains = NULL;

int32_t domains_index = 0;

int32_t IPs_count = 0;
conn_data_t *IPs = NULL;

int32_t try_count = 0;

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

int32_t in_subnet(uint32_t ip, char *subnet_in)
{
    char subnet[100];
    strcpy(subnet, subnet_in);

    uint32_t ip_h = ntohl(ip);

    uint32_t subnet_ip = 0;
    uint32_t subnet_prefix = 0;

    char *slash_ptr = strchr(subnet, '/');
    if (slash_ptr) {
        sscanf(slash_ptr + 1, "%u", &subnet_prefix);
        *slash_ptr = 0;
        if (strlen(subnet) < INET_ADDRSTRLEN) {
            subnet_ip = inet_addr(subnet);
        }
        *slash_ptr = '/';
    }

    uint32_t netip = ntohl(subnet_ip);
    uint32_t netmask = (0xFFFFFFFF << (32 - subnet_prefix) & 0xFFFFFFFF);

    return ((netip & netmask) == (ip_h & netmask));
}

void print_help(void)
{
    printf("Commands:\n"
           "  Required parameters:\n"
           "    -f  \"/example.txt\"  Domains file path\n"
           "    -i  \"/example.txt\"  IPs file path\n"
           "    -n  \"x.x.x.x/xx\"    dev name\n"
           "    -r  \"xxx\"           Request per second\n");
}

static array_hashmap_hash ip_add_hash(const void *add_elem_data)
{
    const uint32_t *elem = add_elem_data;
    return IPs[*elem].IP;
}

static array_hashmap_bool ip_add_cmp(const void *add_elem_data, const void *hashmap_elem_data)
{
    const uint32_t *elem1 = add_elem_data;
    const uint32_t *elem2 = hashmap_elem_data;

    return (IPs[*elem1].IP == IPs[*elem2].IP);
}

static array_hashmap_hash ip_find_hash(const void *find_elem_data)
{
    const uint32_t *elem = find_elem_data;
    return *elem;
}

static array_hashmap_bool ip_find_cmp(const void *find_elem_data, const void *hashmap_elem_data)
{
    const uint32_t *elem1 = find_elem_data;
    const uint32_t *elem2 = hashmap_elem_data;

    return (*elem1 == IPs[*elem2].IP);
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

void *read_raw(__attribute__((unused)) void *arg)
{
    char read_data[PACKET_MAX_SIZE];
    char write_data[PACKET_MAX_SIZE];
    char pseudogram[PACKET_MAX_SIZE];
    char write_data_ack[sizeof(struct iphdr) + sizeof(struct tcphdr)];

    while (true) {
        int32_t nread = read(raw_fd, read_data, PACKET_MAX_SIZE);
        if (nread < (int32_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
            continue;
        }

        struct iphdr *iph_read = (struct iphdr *)read_data;
        if (iph_read->protocol != IPPROTO_TCP) {
            continue;
        }

        struct tcphdr *tcph_read = (struct tcphdr *)(read_data + sizeof(struct iphdr));

        uint32_t res_elem;
        int32_t find_res;
        find_res = array_hashmap_find_elem(ip_map_struct, &(iph_read->saddr), &res_elem);
        if (find_res != array_hashmap_elem_finded) {
            continue;
        }

        if (IPs[res_elem].status == 2) {
            if (ntohs(iph_read->tot_len) == 47) {
                if ((read_data[sizeof(struct iphdr) + sizeof(struct tcphdr)] == 0x15) &&
                    (read_data[sizeof(struct iphdr) + sizeof(struct tcphdr) + 1] == 0x3)) {
                    readed++;
                    IPs[res_elem].status = 0;

                    domains[IPs[res_elem].domain].status++;

                    memset(write_data_ack, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));

                    struct iphdr *iph_send = (struct iphdr *)write_data_ack;
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
                    tcph_send->urg_ptr = 0;

                    uint16_t L4_len = ntohs(iph_send->tot_len) - (iph_send->ihl << 2);
                    pseudo_header_t psh;
                    psh.source_address = iph_send->saddr;
                    psh.dest_address = iph_send->daddr;
                    psh.protocol = htons(IPPROTO_TCP);
                    psh.length = htons(L4_len);
                    memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header_t));
                    memcpy(pseudogram + sizeof(pseudo_header_t),
                           write_data_ack + sizeof(struct iphdr), L4_len);
                    int32_t psize = sizeof(pseudo_header_t) + L4_len;
                    uint16_t checksum_value = checksum(pseudogram, psize);
                    tcph_send->check = checksum_value;
                    iph_send->check = checksum(write_data_ack, iph_send->ihl << 2);

                    write(raw_fd, write_data_ack, ntohs(iph_send->tot_len));
                }
            }
        }

        if (IPs[res_elem].status == 1 && keep_sending) {
            if ((tcph_read->syn == 1) && (tcph_read->ack == 1)) {
                sended++;
                IPs[res_elem].status = 2;

                memset(write_data_ack, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));

                struct iphdr *iph_send = (struct iphdr *)write_data_ack;
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

                struct tcphdr *tcph_send = (struct tcphdr *)(write_data_ack + sizeof(struct iphdr));
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

                uint16_t L4_len = ntohs(iph_send->tot_len) - (iph_send->ihl << 2);
                pseudo_header_t psh;
                psh.source_address = iph_send->saddr;
                psh.dest_address = iph_send->daddr;
                psh.protocol = htons(IPPROTO_TCP);
                psh.length = htons(L4_len);
                memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header_t));
                memcpy(pseudogram + sizeof(pseudo_header_t), write_data_ack + sizeof(struct iphdr),
                       L4_len);
                int32_t psize = sizeof(pseudo_header_t) + L4_len;
                uint16_t checksum_value = checksum(pseudogram, psize);
                tcph_send->check = checksum_value;
                iph_send->check = checksum(write_data_ack, iph_send->ihl << 2);

                write(raw_fd, write_data_ack, ntohs(iph_send->tot_len));

                memset(write_data, 0, PACKET_MAX_SIZE);

                int32_t payload_size =
                    tls_client_hello(write_data + sizeof(struct iphdr) + sizeof(struct tcphdr),
                                     domains[domains_index].domain);
                IPs[res_elem].domain = domains_index;
                domains_index++;

                if (!(domains_index < domains_count)) {
                    domains_index = 0;
                    try_count++;
                }

                if (!(try_count < TRY_COUNT)) {
                    keep_sending = 0;
                }

                iph_send = (struct iphdr *)write_data;
                iph_send->version = 4;
                iph_send->ihl = sizeof(struct iphdr) / 4;
                iph_send->tos = 0;
                iph_send->tot_len =
                    htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size);
                iph_send->id = 0;
                iph_send->frag_off = htons(0x4000);
                iph_send->ttl = 128;
                iph_send->protocol = IPPROTO_TCP;
                iph_send->check = 0;
                iph_send->saddr = iph_read->daddr;
                iph_send->daddr = iph_read->saddr;

                tcph_send = (struct tcphdr *)(write_data + sizeof(struct iphdr));
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

                L4_len = ntohs(iph_send->tot_len) - (iph_send->ihl << 2);
                psh.source_address = iph_send->saddr;
                psh.dest_address = iph_send->daddr;
                psh.protocol = htons(IPPROTO_TCP);
                psh.length = htons(L4_len);
                memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header_t));
                memcpy(pseudogram + sizeof(pseudo_header_t), write_data + sizeof(struct iphdr),
                       L4_len);
                psize = sizeof(pseudo_header_t) + L4_len;
                checksum_value = checksum(pseudogram, psize);
                tcph_send->check = checksum_value;
                iph_send->check = checksum(write_data, iph_send->ihl << 2);

                write(raw_fd, write_data, ntohs(iph_send->tot_len));
            }
        }
    }

    return NULL;
}

void *send_raw(__attribute__((unused)) void *arg)
{
    char write_data[sizeof(struct iphdr) + sizeof(struct tcphdr) + MSS_SIZE];

    uint16_t port = 0;

    while (keep_sending) {
        int32_t current_ips_num = 0;
        int32_t ret = 0;
        do {
            current_ips_num = rand() % IPs_count;
            ret = 0;
            if (IPs[current_ips_num].status != 0) {
                ret = 1;
            } else {
                ret += in_subnet(IPs[current_ips_num].IP, "10.0.0.0/8");
                ret += in_subnet(IPs[current_ips_num].IP, "172.16.0.0/12");
                ret += in_subnet(IPs[current_ips_num].IP, "192.168.0.0/16");
                ret += in_subnet(IPs[current_ips_num].IP, "100.64.0.0/10");
                ret += in_subnet(IPs[current_ips_num].IP, "0.0.0.0/8");
            }
        } while (ret > 0);

        if (port == 0) {
            port = 1000;
        }

        memset(write_data, 0, sizeof(struct iphdr) + sizeof(struct tcphdr) + MSS_SIZE);

        struct iphdr *iph = (struct iphdr *)write_data;
        iph->version = 4;
        iph->ihl = sizeof(struct iphdr) / 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + MSS_SIZE);
        iph->id = 0;
        iph->frag_off = htons(0x4000);
        iph->ttl = 128;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = dev_ip;
        iph->daddr = IPs[current_ips_num].IP;

        IPs[current_ips_num].status = 1;

        struct tcphdr *tcph = (struct tcphdr *)(write_data + sizeof(struct iphdr));
        tcph->source = htons(port++);
        tcph->dest = htons(PORT_TLS);
        tcph->seq = rand();
        tcph->ack_seq = 0;
        tcph->res1 = 0;
        tcph->doff = (sizeof(struct tcphdr) + MSS_SIZE) / 4;
        tcph->syn = 1;
        tcph->window = 0xffff;
        tcph->check = 0;
        tcph->urg_ptr = 0;

        char *tcp_opt_ptr = write_data + sizeof(struct iphdr) + sizeof(struct tcphdr);
        tcp_opt_ptr[0] = 2;
        tcp_opt_ptr[1] = 4;
        *((uint16_t *)(&tcp_opt_ptr[2])) = htons(1400);

        uint16_t L4_len = ntohs(iph->tot_len) - (iph->ihl << 2);
        pseudo_header_t psh;
        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.protocol = htons(IPPROTO_TCP);
        psh.length = htons(L4_len);
        char pseudogram[PACKET_MAX_SIZE];
        memcpy(pseudogram, (char *)&psh, sizeof(pseudo_header_t));
        memcpy(pseudogram + sizeof(pseudo_header_t), write_data + sizeof(struct iphdr), L4_len);
        int32_t psize = sizeof(pseudo_header_t) + L4_len;
        uint16_t checksum_value = checksum(pseudogram, psize);
        tcph->check = checksum_value;
        iph->check = checksum(write_data, iph->ihl << 2);

        write(raw_fd, write_data, ntohs(iph->tot_len));

        usleep(1000000 / rps / coeff);
    }

    return NULL;
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

#define STRLEN(s) ((sizeof(s) / sizeof(s[0])) - 1)
#define ETH_STRLEN STRLEN("00:11:22:33:44:55")

static void eth_bin2str(const unsigned char *src, char *dst)
{
    sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned int)src[0], (unsigned int)src[1],
            (unsigned int)src[2], (unsigned int)src[3], (unsigned int)src[4], (unsigned int)src[5]);
}

int32_t main(int32_t argc, char *argv[])
{
    printf("Domains block test started\n");

    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGINT signal handler main\n");
    }

    if (signal(SIGSEGV, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGSEGV signal handler main\n");
    }

    if (signal(SIGTERM, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGTERM signal handler main\n");
    }

    printf("Launch parameters:\n");

    char domains_file_path[PATH_MAX];
    memset(domains_file_path, 0, PATH_MAX);

    char IPs_file_path[PATH_MAX];
    memset(IPs_file_path, 0, PATH_MAX);

    char dev_name[IFNAMSIZ];
    memset(dev_name, 0, IFNAMSIZ);

    //Args
    {
        for (int32_t i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "-f")) {
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

    //Open socket
    {
        raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (raw_fd < 0) {
            errmsg("Can't open a raw socket ETH_P_ALL\n");
        }

        int32_t ret = 0;
        ret = setsockopt(raw_fd, SOL_SOCKET, SO_BINDTODEVICE, dev_name, strlen(dev_name));
        if (ret < 0) {
            errmsg("Can't bind to device %s\n", dev_name);
        }

        struct ifreq ifreq;
        memset(&ifreq, 0, sizeof(ifreq));
        strcpy(ifreq.ifr_name, dev_name);

        ret = ioctl(raw_fd, SIOCGIFHWADDR, &ifreq);
        if (ret < 0) {
            errmsg("Can't get mac address of interface %s\n", dev_name);
        }
        char dev_src[ETH_STRLEN + 1];
        eth_bin2str((const unsigned char *)ifreq.ifr_hwaddr.sa_data, dev_src);
        printf("dev_src_mac %s\n", dev_src);

        memset(&ifreq, 0, sizeof(ifreq));
        strcpy(ifreq.ifr_name, dev_name);

        ret = ioctl(raw_fd, SIOCGIFADDR, &ifreq);
        if (ret < 0) {
            errmsg("Can't get ip address of interface %s\n", dev_name);
        }
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(struct sockaddr_in));
        memcpy(&sin, &ifreq.ifr_addr, sizeof(struct sockaddr));
        struct in_addr src_ip_s;
        src_ip_s.s_addr = sin.sin_addr.s_addr;
        printf("dev_src_ip %s\n", inet_ntoa(src_ip_s));
    }
    //Open socket

    char *domains_file_data = NULL;

    //Domains read
    {
        FILE *domains_fp = fopen(domains_file_path, "r");
        if (!domains_fp) {
            errmsg("Can't open file %s\n", domains_file_path);
        }

        fseek(domains_fp, 0, SEEK_END);
        int64_t domains_file_size_add = ftell(domains_fp);
        fseek(domains_fp, 0, SEEK_SET);

        domains_file_data = (char *)malloc(domains_file_size_add);

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
    }
    //Domains read

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

        IPs = (conn_data_t *)malloc(IPs_count * sizeof(conn_data_t));
        memset(IPs, 0, IPs_count * sizeof(conn_data_t));

        ip_map_struct = array_hashmap_init(IPs_count, 1.0, sizeof(uint32_t));
        if (ip_map_struct == NULL) {
            errmsg("No free memory for ip_map_struct\n");
        }

        array_hashmap_set_func(ip_map_struct, ip_add_hash, ip_add_cmp, ip_find_hash, ip_find_cmp,
                               ip_find_hash, ip_find_cmp);

        char *IP_start = IPs_file_data;
        for (int32_t i = 0; i < IPs_count; i++) {
            IPs[i].IP = inet_addr(IP_start);

            array_hashmap_add_elem(ip_map_struct, &i, NULL, NULL);

            IP_start = strchr(IP_start, 0) + 1;
        }

        free(IPs_file_data);

        fclose(IPs_fp);
    }
    //IPs read

    printf("Domains count: %d\n", domains_count);
    printf("IPs count    : %d\n", IPs_count);

    char buffer[BUFSIZ];
    int32_t len;

    while (1) {
        len = recvfrom(raw_fd, buffer, sizeof(buffer), 0, NULL, 0);

        if (len >= (int32_t)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
            struct ethhdr *eth_h = (struct ethhdr *)buffer;

            if (eth_h->h_proto == htons(ETH_P_IP)) {
                char src[ETH_STRLEN + 1];
                char dst[ETH_STRLEN + 1];

                eth_bin2str(eth_h->h_source, src);
                eth_bin2str(eth_h->h_dest, dst);

                printf("src dst %s %s\n", src, dst);

                struct iphdr *ip_h = (struct iphdr *)(buffer + sizeof(struct ethhdr));
                struct in_addr src_ip_s;
                src_ip_s.s_addr = ip_h->saddr;
                struct in_addr dst_ip_s;
                dst_ip_s.s_addr = ip_h->daddr;
                printf("src dst %s %s\n", inet_ntoa(src_ip_s), inet_ntoa(dst_ip_s));
            }
        }
    }

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

    int32_t sended_old = 0;
    int32_t readed_old = 0;

    int32_t exit_wait = 0;

    printf("Send_RPS Read_RPS Sended Readed\n");
    while (true) {
        sleep(1);

        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        printf("\n%d %02d.%02d.%04d %02d:%02d:%02d\n", try_count, tm_struct->tm_mday,
               tm_struct->tm_mon + 1, tm_struct->tm_year + 1900, tm_struct->tm_hour,
               tm_struct->tm_min, tm_struct->tm_sec);
        printf("%08d %08d %06d %06d\n", sended - sended_old, readed - readed_old, sended, readed);

        if (readed == readed_old) {
            exit_wait++;
        } else {
            exit_wait = 0;
        }

        if (exit_wait >= EXIT_WAIT_SEC) {
            break;
        }

        coeff *= (1.0 * rps) / (sended - sended_old);

        sended_old = sended;
        readed_old = readed;
    }

    //Write blocked
    {
        FILE *blocked_fp = fopen("blocked.txt", "w");
        if (!blocked_fp) {
            errmsg("Can't open file blocked.txt\n");
        }

        for (int32_t i = 0; i < domains_count; i++) {
            if (domains[i].status <= TRY_COUNT / 3) {
                fprintf(blocked_fp, "%d %s\n", domains[i].status, domains[i].domain);
            }
        }

        fclose(blocked_fp);
    }
    //Write blocked

    close(raw_fd);

    free(domains_file_data);
    free(domains);

    free(IPs);

    array_hashmap_del(&ip_map_struct);

    return EXIT_SUCCESS;
}
