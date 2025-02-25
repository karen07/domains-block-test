#include "domains-block-test.h"

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
           "    -i  \"/example.txt\"  IPs file path\n");
}

int32_t main(int32_t argc, char *argv[])
{
    printf("Domains block test started\n");
    printf("Launch parameters:\n");

    char domains_file_path[PATH_MAX];
    memset(domains_file_path, 0, PATH_MAX);

    char IPs_file_path[PATH_MAX];
    memset(IPs_file_path, 0, PATH_MAX);

    //Args
    {
        for (int32_t i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "-f")) {
                if (i != argc - 1) {
                    printf("Get domains from file %s\n", argv[i + 1]);
                    if (strlen(argv[i + 1]) < PATH_MAX) {
                        strcpy(domains_file_path, argv[i + 1]);
                    }
                    i++;
                }
                continue;
            }
            if (!strcmp(argv[i], "-i")) {
                if (i != argc - 1) {
                    printf("Get IPs from file %s\n", argv[i + 1]);
                    if (strlen(argv[i + 1]) < PATH_MAX) {
                        strcpy(IPs_file_path, argv[i + 1]);
                    }
                    i++;
                }
                continue;
            }
            print_help();
            errmsg("Unknown command %s\n", argv[i]);
        }

        if (domains_file_path[0]) {
            print_help();
            errmsg("Programm need domains file path\n");
        }

        if (IPs_file_path[0]) {
            print_help();
            errmsg("Programm need IPs file path\n");
        }
    }
    //Args

    char **domains = NULL;
    int32_t domains_count = 0;

    //domains read
    {
        FILE *domains_fp = fopen(domains_file_path, "r");
        if (!domains_fp) {
            errmsg("Error opening file %s\n", domains_file_path);
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

        domains = (char **)malloc(domains_count * sizeof(char *));

        char *domain_start = domains_file_data;
        for (int32_t i = 0; i < domains_count; i++) {
            domains[i] = domain_start;

            domain_start = strchr(domain_start, 0) + 1;
        }
    }
    //domains read

    uint32_t *IPs = NULL;
    int32_t IPs_count = 0;

    //IPs read
    {
        FILE *IPs_fp = fopen(IPs_file_path, "r");
        if (!IPs_fp) {
            errmsg("Error opening file %s\n", IPs_file_path);
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
    }
    //IPs read

    printf("Domains count: %d\n", domains_count);
    printf("IPs count: %d\n", IPs_count);

    int32_t *domains_status = (int32_t *)malloc(domains_count * sizeof(int32_t));
    memset(domains_status, 0, domains_count * sizeof(int32_t));

    struct pollfd *pollfd = (struct pollfd *)malloc(MAX_SOCKET_COUNT * sizeof(struct pollfd));
    char *send_data = (char *)malloc(MAX_SOCKET_COUNT * PACKET_MAX_SIZE);
    char *read_data = (char *)malloc(PACKET_MAX_SIZE);
    char *ready_to_write = (char *)malloc(MAX_SOCKET_COUNT);
    int32_t *sock_to_domain = (int32_t *)malloc(MAX_SOCKET_COUNT * sizeof(int32_t));
    int32_t *sock_to_ip = (int32_t *)malloc(MAX_SOCKET_COUNT * sizeof(int32_t));

    for (int32_t k = 0; k < TRY_COUNT; k++) {
        int32_t domain_index = 0;

        printf("\nTry %d\n", k);

        while (domain_index < domains_count) {
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                pollfd[i].fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            }

            int32_t create_err = 0;
            int32_t connect_err = 0;
            int32_t pollout_err = 0;
            int32_t write_err = 0;
            int32_t timeout_err = 0;
            int32_t pollin_err = 0;

            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    int32_t ret = 0;
                    int32_t current_ips_num = 0;
                    do {
                        current_ips_num = rand() % IPs_count;
                        ret = 0;
                        ret += in_subnet(IPs[current_ips_num], "10.0.0.0/8");
                        ret += in_subnet(IPs[current_ips_num], "172.16.0.0/12");
                        ret += in_subnet(IPs[current_ips_num], "192.168.0.0/16");
                        ret += in_subnet(IPs[current_ips_num], "100.64.0.0/10");
                        ret += in_subnet(IPs[current_ips_num], "0.0.0.0/30");
                    } while (ret > 0);

                    struct sockaddr_in servaddr;
                    memset(&servaddr, 0, sizeof(servaddr));
                    servaddr.sin_family = AF_INET;
                    servaddr.sin_addr.s_addr = IPs[current_ips_num];
                    servaddr.sin_port = htons(PORT_TLS);

                    sock_to_ip[i] = IPs[current_ips_num];

                    if (connect(pollfd[i].fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
                        if (errno != EINPROGRESS) {
                            close(pollfd[i].fd);
                            pollfd[i].fd = -1;
                            connect_err++;
                        }
                    }
                } else {
                    create_err++;
                }
            }

            //Ready to write
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    pollfd[i].events = POLLOUT;
                } else {
                    pollfd[i].events = 0;
                }
                pollfd[i].revents = 0;
            }

            memset(ready_to_write, 0, MAX_SOCKET_COUNT);

            while (poll(pollfd, MAX_SOCKET_COUNT, POLL_SLEEP_TIME) > 0) {
                for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                    if (pollfd[i].revents != 0 && pollfd[i].revents != POLLOUT) {
                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;
                        pollout_err++;
                    }
                    if (pollfd[i].revents == POLLOUT) {
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;

                        ready_to_write[i] = 1;
                    }
                }
            }
            //Ready to write

            //Write
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    if (ready_to_write[i] == 1) {
                        if (domain_index < domains_count) {
                            sock_to_domain[i] = domain_index;

                            char *send_data_local = &send_data[i * PACKET_MAX_SIZE];

                            int32_t send_size = 0;
                            send_size = tls_client_hello(send_data_local, domains[domain_index]);

                            int32_t sended = 0;
                            sended = write(pollfd[i].fd, send_data_local, send_size);
                            if (sended != send_size) {
                                close(pollfd[i].fd);
                                pollfd[i].fd = -1;
                                write_err++;
                            }

                            domain_index++;
                        } else {
                            close(pollfd[i].fd);
                            pollfd[i].fd = -1;
                        }
                    } else {
                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        timeout_err++;
                    }
                }
            }
            //Write

            //Ready to read
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    pollfd[i].events = POLLIN;
                } else {
                    pollfd[i].events = 0;
                }
                pollfd[i].revents = 0;
            }

            while (poll(pollfd, MAX_SOCKET_COUNT, POLL_SLEEP_TIME) > 0) {
                for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                    if (pollfd[i].revents != 0 && pollfd[i].revents != POLLIN) {
                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;
                        pollin_err++;
                    }
                    if (pollfd[i].revents == POLLIN) {
                        int32_t readed = 0;
                        readed = read(pollfd[i].fd, read_data, PACKET_MAX_SIZE);
                        if (readed == 7) {
                            if (read_data[0] == 0x15 && read_data[1] == 0x3) {
                                domains_status[sock_to_domain[i]]++;
                                //printf("Karen %s\n", domains[sock_to_domain[i]]);
                                //struct in_addr end_subnet_ip_addr;
                                //end_subnet_ip_addr.s_addr = sock_to_ip[i];
                                //printf("%s\n", inet_ntoa(end_subnet_ip_addr));
                            }
                        }

                        close(pollfd[i].fd);
                        pollfd[i].fd = -1;
                        pollfd[i].events = 0;
                        pollfd[i].revents = 0;
                    }
                }
            }
            //Ready to read

            //Find blocked
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1 && pollfd[i].events == POLLIN) {
                    domains_status[sock_to_domain[i]]--;
                    //        if (domains_status[sock_to_domain[i]] != 2) {
                    //            domains_status[sock_to_domain[i]] = 1;
                    //        }
                }
            }
            //Find blocked

            //Close
            for (int32_t i = 0; i < MAX_SOCKET_COUNT; i++) {
                if (pollfd[i].fd != -1) {
                    close(pollfd[i].fd);
                }
            }
            //Close

            //Stat
            int32_t in_work_count = 0;
            int32_t blocked_count = 0;
            int32_t notblocked_count = 0;
            for (int32_t i = 0; i < domains_count; i++) {
                if (domains_status[i] == 0) {
                    in_work_count++;
                }
                if (domains_status[i] < 0) {
                    blocked_count++;
                }
                if (domains_status[i] > 0) {
                    notblocked_count++;
                }
            }
            printf("\n");
            printf("in_work_count %d ", in_work_count);
            printf("blocked_count %d ", blocked_count);
            printf("notblocked_count %d ", notblocked_count);
            printf("domain_index %d ", domain_index);
            printf("\n");
            printf("opened %d ", MAX_SOCKET_COUNT);
            printf("create_err %d ", create_err);
            printf("connect_err %d ", connect_err);
            printf("pollout_err %d ", pollout_err);
            printf("write_err %d ", write_err);
            printf("timeout_err %d ", timeout_err);
            printf("pollin_err %d ", pollin_err);
            printf("\n");
            //Stat
        }
    }

    FILE *blocked_fp = fopen("blocked.txt", "w");
    if (!blocked_fp) {
        errmsg("Error opening file blocked.txt\n");
    }

    for (int32_t i = 0; i < domains_count; i++) {
        if (domains_status[i] < 0) {
            fprintf(blocked_fp, "%s\n", domains[i]);
        }
    }

    return EXIT_SUCCESS;
}
