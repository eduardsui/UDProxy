#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <inttypes.h>
#ifdef _WIN32
    #ifdef _WIN32_WINNT
        #undef _WIN32_WINNT
    #endif
    #define _WIN32_WINNT    0x501

    #define _WINSOCKAPI_
    #define WIN32_LEAN_AND_MEAN

    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>

    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <poll.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

#define ALLOW_FIXED_DESTINATION     0
#define ALLOW_ADDRESS               1
#define ALLOW_ALL                   2

#define SOCKET_CLEAN_TIMEOUT        2880

#define DEBUG_PRINT(f, ...)         fprintf(stderr, "%s [%i] ",timestamp(), __LINE__), fprintf(stderr, (f), ##__VA_ARGS__)

static char * timestamp() {
    time_t now = time(NULL); 
    char * time = asctime(gmtime(&now));
    time[strlen(time)-1] = '\0';    // Remove \n
    return time;
}

struct proxy_socket {
    int socket;
    int socket_pair;
    unsigned char is_sip;
    time_t timestamp;
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
    uint32_t call_id;
    unsigned char bind;
    unsigned char remote_mode;
};

typedef int (socket_proxy_t)(struct proxy_socket *socket_in, struct proxy_socket **sockets);

static uint32_t murmurhash(const char *key) {
    if ((!key) || (!key[0]))
        return 0;
    uint32_t len = strlen(key);
    uint32_t seed = 0;
    uint32_t c1 = 0xcc9e2d51;
    uint32_t c2 = 0x1b873593;
    uint32_t r1 = 15;
    uint32_t r2 = 13;
    uint32_t m = 5;
    uint32_t n = 0xe6546b64;
    uint32_t h = 0;
    uint32_t k = 0;
    uint8_t *d = (uint8_t *) key;
    const uint32_t *chunks = NULL;
    const uint8_t *tail = NULL;
    int i = 0;
    int l = len / 4;

    h = seed;
    chunks = (const uint32_t *) (d + l * 4);
    tail = (const uint8_t *) (d + l * 4);

    for (i = -l; i != 0; ++i) {
        k = chunks[i];
        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;
        h ^= k;
        h = (h << r2) | (h >> (32 - r2));
        h = h * m + n;
    }

    k = 0;

    switch (len & 3) { // `len % 4'
        case 3: k ^= (tail[2] << 16);
        case 2: k ^= (tail[1] << 8);
        case 1:
            k ^= tail[0];
            k *= c1;
            k = (k << r1) | (k >> (32 - r1));
            k *= c2;
            h ^= k;
    }

    h ^= len;

    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);

    return h;
}

#ifdef _WIN32
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt) {
    if (af == AF_INET) {
        struct sockaddr_in in;
        memset(&in, 0, sizeof(in));
        in.sin_family = AF_INET;
        memcpy(&in.sin_addr, src, sizeof(struct in_addr));
        getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
        return dst;
    } else if (af == AF_INET6) {
        struct sockaddr_in6 in;
        memset(&in, 0, sizeof(in));
        in.sin6_family = AF_INET6;
        memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
        getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
        return dst;
    }
    return NULL;
}
#endif

char *getIp(const struct sockaddr *sa, char *s, size_t maxlen) {
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, maxlen);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, maxlen);
            break;
        default:
            return NULL;
    }
    return s;
}

int createSocket(const char *ip, int port, struct sockaddr_in *server_addr) {
    int sockfd;
    int n;
 
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket error");
        return -1;
    }
 
    memset(server_addr, 0, sizeof(struct sockaddr_in));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port);

    struct hostent *host = gethostbyname(ip);
    if (host) {
        server_addr->sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;
    } else
        server_addr->sin_addr.s_addr = inet_addr(ip);
 
    n = bind(sockfd, (struct sockaddr*)server_addr, sizeof(struct sockaddr_in));
    if (n < 0) {
        DEBUG_PRINT("error binding to %s:%i\n", ip, port);
        perror("bind error");
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return -1;
    }

#ifdef _WIN32
    u_long noBlock = 1;
    ioctlsocket(sockfd, FIONBIO, &noBlock);
#else
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

    return sockfd;
}

void clearSockets(struct proxy_socket *sockets, int timeout_seconds, uint32_t call_id_hash) {
    int socket_count = 0;
    time_t now = time(NULL);
    int needs_cleaning = 0;
    int i;
    int j;

    while (sockets[socket_count].socket > 0) {
        if (!sockets[socket_count].is_sip) {
            if (((call_id_hash) && (sockets[socket_count].call_id == call_id_hash)) || (now - sockets[socket_count].timestamp >= timeout_seconds)) {
                needs_cleaning ++;

                if (sockets[socket_count].socket_pair > 0)
                    sockets[sockets[socket_count].socket_pair - 1].timestamp = 0;
            }
        }
        socket_count ++;
    }

    if (needs_cleaning) {
        i = 0;
        while (i < socket_count) {
            if (((call_id_hash) && (sockets[i].call_id == call_id_hash)) || (now - sockets[i].timestamp >= timeout_seconds)) {
#ifdef _WIN32
                closesocket(sockets[i].socket);
#else
                close(sockets[i].socket);
#endif
                for (j = i; j < socket_count; j ++)
                    sockets[j] = sockets[j + 1];
                socket_count --;
            } else
                i ++;
        }
        DEBUG_PRINT("cleaned %i sockets\n", needs_cleaning);
    }
}

int buildAddress(struct proxy_socket *socket, const char *ip, int port) {
    if ((!socket) || (!ip))
        return -1;

    if (port == 0) {
        socket->remote_mode = ALLOW_ADDRESS;
        port = 5060;
    }
    if (strcmp(ip, "0.0.0.0") == 0) {
        DEBUG_PRINT("WARNING: allowing all trafic\n");
        socket->remote_mode = ALLOW_ALL;
    }

    memset(&socket->remote_addr, 0, sizeof(struct sockaddr_in));
    socket->remote_addr.sin_family = AF_INET;
    socket->remote_addr.sin_port = htons(port);

    struct hostent *host = gethostbyname(ip);
    if ((host) && (host->h_length > 0))
        socket->remote_addr.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;
    else
        socket->remote_addr.sin_addr.s_addr = inet_addr(ip);

    DEBUG_PRINT("added ip/port: %s:%i\n", ip, port);
    return 0;
}

int createMediaProxy(const char *call_id, const char *ip, int port, struct proxy_socket *socket_in, struct proxy_socket **sockets) {
    if ((!ip) || (!ip[0]) || (port <= 0) || (!socket_in) || (!socket_in->socket_pair) || (!sockets) || (!call_id) || (!call_id[0]))
        return -1;

    DEBUG_PRINT("audio proxy for %s: %s:%i\n", call_id, ip, port);

    // may get realloc'ed (copy it)
    struct proxy_socket socket_out = (*sockets)[socket_in->socket_pair - 1];
    uint32_t call_id_hash = murmurhash(call_id);

    char remote_ip_buf[0x100];
    char local_ip_buf[0x100];

    int socket_count = 0;
    int hash_found = 0;
    while ((*sockets)[socket_count].socket > 0)
        socket_count ++;

    if (hash_found)
        return 0;

    socket_count += 2;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_addr = socket_in->local_addr;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0) {
        char *remote_ip = getIp((struct sockaddr *)&server_addr, remote_ip_buf, sizeof(remote_ip_buf));
        DEBUG_PRINT("already binding to %s:%i\n", remote_ip, port);
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return -1;
    }

    int sockfd2 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_addr2 = socket_out.local_addr;
    server_addr2.sin_port = htons(port);

    struct proxy_socket *new_sockets = (struct proxy_socket *)realloc(*sockets, (socket_count + 1) * sizeof(struct proxy_socket));
    if (!new_sockets) {
        DEBUG_PRINT("error allocating buffer\n");
#ifdef _WIN32
        closesocket(sockfd);
        closesocket(sockfd2);
#else
        close(sockfd);
        close(sockfd2);
#endif
        return -1;
    }

#ifdef _WIN32
    u_long noBlock = 1;
    ioctlsocket(sockfd, FIONBIO, &noBlock);
    noBlock = 1;
    ioctlsocket(sockfd2, FIONBIO, &noBlock);
#else
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(sockfd2, F_GETFL, 0);
    fcntl(sockfd2, F_SETFL, flags | O_NONBLOCK);
#endif

    time_t now = time(NULL);

    new_sockets[socket_count - 2].socket = sockfd;
    new_sockets[socket_count - 2].socket_pair = socket_count;
    new_sockets[socket_count - 2].is_sip = 0;
    new_sockets[socket_count - 2].timestamp = now;
    new_sockets[socket_count - 2].local_addr = server_addr;
    new_sockets[socket_count - 2].remote_addr = socket_in->remote_addr;
    new_sockets[socket_count - 2].remote_addr.sin_port = htons(port);
    new_sockets[socket_count - 2].call_id = call_id_hash;
    new_sockets[socket_count - 2].bind = 1;
    new_sockets[socket_count - 2].remote_mode = ALLOW_ADDRESS;

    new_sockets[socket_count - 1].socket = sockfd2;
    new_sockets[socket_count - 1].socket_pair = socket_count - 1;
    new_sockets[socket_count - 1].is_sip = 0;
    new_sockets[socket_count - 1].timestamp = now;
    new_sockets[socket_count - 1].local_addr = server_addr2;
    new_sockets[socket_count - 1].remote_addr = socket_out.remote_addr;
    new_sockets[socket_count - 1].remote_addr.sin_port = htons(port);
    new_sockets[socket_count - 1].call_id = call_id_hash;
    new_sockets[socket_count - 1].bind = 0;
    new_sockets[socket_count - 1].remote_mode = ALLOW_ADDRESS;

    char *remote_ip = getIp((struct sockaddr *)&server_addr, remote_ip_buf, sizeof(remote_ip_buf));
    char *local_ip = getIp((struct sockaddr *)&new_sockets[socket_count - 2].remote_addr, local_ip_buf, sizeof(local_ip_buf));
    DEBUG_PRINT("set pair %s:%i => %s:%i\n", remote_ip, (int)ntohs(server_addr.sin_port), local_ip, (int)ntohs(new_sockets[socket_count - 2].remote_addr.sin_port));

    memset(&new_sockets[socket_count], 0, sizeof(struct proxy_socket));

    *sockets = new_sockets;

    return 0;
}

char *filterBuffer(char *buffer, int *size, struct proxy_socket *socket_in, struct proxy_socket **sockets) {
    if ((!buffer) || (!size) || (!(*size)))
        return buffer;

    // for switching ip in contact field
    char *buffer_clone = (char *)malloc(*size + 1024);
    memcpy(buffer_clone, buffer, *size);
    buffer_clone[*size] = 0;

    char *buf2 = buffer_clone;
    int has_sdp = 0;
    int in_content = 0;
    char *buf3;
    char ip[0x100];
    char call_id[0x400];
    int port = 0;
    int content_length_offset = 0;
    int next_header = 0;
    int sdp_content_offset = 0;
    ip[0] = 0;
    call_id[0] = 0;
    char *next_buf;

    int sdp_size = 0;
    char new_sdp[4096];
    new_sdp[sdp_size] = 0;

    char ip_buf[0x100];

    // may get realloc'ed (copy it)
    struct proxy_socket socket_out = (*sockets)[socket_in->socket_pair - 1];

    int remove_session = 0;
    if (*size > 12) {
        if ((memcmp(buffer, "BYE", 3) == 0) || (memcmp(buffer, "CANCEL", 6) == 0))
            remove_session = 1;
    }

    while ((buf2) && (buf2[0])) {
        next_buf = strstr(buf2, "\r\n");
        if (next_buf)
            next_buf[0] = 0;

        if (in_content) {
            if ((buf2[0]) && (buf2[1])) {
                switch (buf2[0]) {
                    case 'c':
                        buf3 = strstr(buf2, "IP4 ");
                        if (!buf3)
                            buf3 = strstr(buf2, "IP6 ");
                        if (buf3) {
                            buf3 += 4;
                            char *ref_buf = buf3;
                            unsigned int ip_index = 0;
                            while (*buf3) {
                                if ((*buf3 == '/') || (*buf3 == '\r') || (*buf3 == '\n'))
                                    break;
                                if ((*buf3 == ' ') || (*buf3 == '\t')) {
                                    buf3 ++;
                                    continue;
                                }
                                if (ip_index >= sizeof(ip) - 1)
                                    break;
                                ip[ip_index ++] = *buf3;
                                ip[ip_index] = 0;
                                buf3 ++;
                            }
                            *ref_buf = 0;

                            strncat(new_sdp, buf2, sizeof(new_sdp) - sdp_size);
                            sdp_size += strlen(buf2);

                            char *remote_ip = getIp((struct sockaddr *)&socket_out.local_addr, ip_buf, sizeof(ip_buf));
                            if (remote_ip) {
                                strncat(new_sdp, remote_ip, sizeof(new_sdp) - sdp_size);
                                sdp_size += strlen(remote_ip);
                            }
                        } else {
                            strncat(new_sdp, buf2, sizeof(new_sdp) - sdp_size);
                            sdp_size += strlen(buf2);
                        }
                        break;
                    case 'm':
                        buf3 = strstr(buf2, "audio ");
                        if (!buf3)
                            buf3 = strstr(buf2, "video ");
                        if (buf3)
                            port = atoi(buf3 + 6);
                        // port information
                        strncat(new_sdp, buf2, sizeof(new_sdp) - sdp_size);
                        sdp_size += strlen(buf2);
                        break;
                    case '\r':
                    case '\n':
                        continue;
                    default:
                        strncat(new_sdp, buf2, sizeof(new_sdp) - sdp_size);
                        sdp_size += strlen(buf2);
                        break;
                }
                strncat(new_sdp, "\r\n", sizeof(new_sdp) - sdp_size);
                sdp_size += 2;
            }
        } else {
            if (strncasecmp(buf2, "Call-ID:", 8) == 0) {
                buf2 += 8;
                while ((*buf2 == ' ') || (*buf2 == '\t'))
                    buf2++;

                strncpy(call_id, buf2, sizeof(call_id) - 1);
            } else
            if (strncasecmp(buf2, "From:", 6) == 0) {
                // from field
            } else
            if (strncasecmp(buf2, "To:", 3) == 0) {
                // to field
            } else
            if (strncasecmp(buf2, "Contact:", 8) == 0) {
                char *address_offset = strchr(buf2, '@');
                if (address_offset) {
                    address_offset ++;
                    char *end_offset = strchr(address_offset, '>');
                    if (end_offset) {
                        int ip_port_len = end_offset - address_offset;
                        if (ip_port_len > 0) {
                            char *ip_rewrite = getIp((struct sockaddr *)&socket_out.local_addr, ip_buf, sizeof(ip_buf));
                            if (ip_rewrite) {
                                char ip_port_buffer[0x140];
                                ip_port_buffer[0] = 0;
                                snprintf(ip_port_buffer, sizeof(ip_port_buffer), "%s:%i", ip_rewrite, (int)ntohs(socket_out.local_addr.sin_port));
                                int new_ip_port_len = strlen(ip_port_buffer);
                                if (new_ip_port_len == ip_port_len) {
                                    // no memmove
                                    memcpy(buffer + (address_offset - buffer_clone), ip_port_buffer, new_ip_port_len);
                                } else {
                                    int delta = new_ip_port_len - ip_port_len;
                                    memmove(buffer + (address_offset - buffer_clone) + new_ip_port_len, buffer + (address_offset - buffer_clone) + ip_port_len, *size - (address_offset - buffer_clone));
                                    memcpy(buffer + (address_offset - buffer_clone), ip_port_buffer, new_ip_port_len);

                                    *size += delta;
                                    buffer[*size] = 0;
                                    memcpy(buffer_clone, buffer, *size);
                                    buffer_clone[*size] = 0;

                                    next_buf += delta;
                                }
                            }
                        }
                    }
                }
            } else
            if (strncasecmp(buf2, "Content-length:", 15) == 0) {
                content_length_offset = buf2 - buffer_clone;
                next_header = next_buf - buffer_clone;
                next_header += 2;
            } else
            if ((strncasecmp(buf2, "Content-type: ", 14) == 0) && (strstr(buf2, "application/sdp"))) {
                has_sdp = 1;
            } else
            if (((!buf2[0]) || (strncmp(buf2, "\r\n", 2) == 0)) && (has_sdp)) {
                // empty line, start of SDP packet
                in_content = 1;
                sdp_content_offset = buf2 - buffer_clone;
            }
        }
        buf2 = next_buf;
        if (buf2)
            buf2 += 2;
    }
    if (port > 0)
        createMediaProxy(call_id, ip, port, &socket_out, sockets);

    if ((new_sdp[0]) && (sdp_size > 2) && (content_length_offset > 0) && (content_length_offset < *size) && (sdp_content_offset < *size) && (sdp_content_offset > content_length_offset) && (next_header > 0)) {
        int buf_size = *size + sdp_size + 8192;
        char *new_buffer = (char *)malloc(buf_size);
        memset(new_buffer, 0, buf_size);

        char content_length[0x100];
        content_length[0] = 0;
        snprintf(content_length, sizeof(content_length), "Content-length: %i\r\n", sdp_size);

        strncpy(new_buffer, buffer, content_length_offset);
        strcat(new_buffer, content_length);
        strncat(new_buffer, buffer + next_header, sdp_content_offset - next_header);
        strcat(new_buffer, "\r\n");
        strcat(new_buffer, new_sdp);

        // replace message buffer
        free(buffer);
        buffer = new_buffer;
        *size = strlen(new_buffer);

    }

    free(buffer_clone);

    if ((remove_session) && (call_id[0])) {
        DEBUG_PRINT("removing session %s\n", call_id);
        clearSockets(*sockets, SOCKET_CLEAN_TIMEOUT, murmurhash(call_id));
    }
    return buffer;
}

int proxyIO(struct proxy_socket *socket_in, struct proxy_socket **sockets) {
    if (!socket_in)
        return -1;

    time_t now = time(NULL);

    socklen_t addr_size;
    struct sockaddr_in client_addr;

    int written = -1;
    // reserve a little bit more for "in place" rewrite
    char *buffer = (char *)malloc(0x10000 + 1024);
    addr_size = sizeof(client_addr);
    int size = recvfrom(socket_in->socket, buffer, 0xFFFF, 0, (struct sockaddr *)&client_addr, &addr_size);
    if (size > 0) {
        socket_in->timestamp = now;
        if (socket_in->is_sip) {
            struct proxy_socket *socket_out = &(*sockets)[socket_in->socket_pair - 1];

            if ((socket_in->remote_mode != ALLOW_ALL) &&
                (client_addr.sin_addr.s_addr != socket_in->remote_addr.sin_addr.s_addr) && 
                (client_addr.sin_addr.s_addr != socket_out->remote_addr.sin_addr.s_addr)) {
                char remote_ip_buf[0x100];
                char *remote_ip = getIp((struct sockaddr *)&client_addr, remote_ip_buf, sizeof(remote_ip_buf));
                DEBUG_PRINT("invalid source IP: %s\n", remote_ip);
                free(buffer);
                return 0;
            }
            // ensure null-terminated and followed by zeros
            memset(buffer + size, 0, 0x10000 + 1024 - size);
            buffer = filterBuffer(buffer, &size, socket_in, sockets);
        }
        if (socket_in->socket_pair > 0) {
            struct proxy_socket *socket_out = &(*sockets)[socket_in->socket_pair - 1];
            if (socket_out->remote_mode == ALLOW_ADDRESS) {
                // same address, different port (NAT? - update port)
                if (client_addr.sin_addr.s_addr == socket_out->remote_addr.sin_addr.s_addr)
                    socket_out->remote_addr.sin_port = client_addr.sin_port;
            } else
            if (socket_out->remote_mode == ALLOW_ALL) {
                // NAT? - update address
                socket_out->remote_addr = client_addr;
            }

            socket_out->timestamp = now;
            written = sendto(socket_out->socket, buffer, size, 0, (struct sockaddr*)&socket_in->remote_addr, sizeof(socket_in->remote_addr));
        }
        if (written < 0) {
            if ((client_addr.sin_addr.s_addr == socket_in->remote_addr.sin_addr.s_addr) && (client_addr.sin_port == socket_in->remote_addr.sin_port)) {
                // write will cause echo
                char remote_ip_buf[0x100];
                char local_ip_buf[0x100];
                char *remote_ip = getIp((struct sockaddr *)&client_addr, remote_ip_buf, sizeof(remote_ip_buf));
                char *local_ip = getIp((struct sockaddr *)&socket_in->remote_addr, local_ip_buf, sizeof(local_ip_buf));
                DEBUG_PRINT("RTP echo pachet %s:%i => %s:%i\n", remote_ip, (int)ntohs(client_addr.sin_port), local_ip, (int)ntohs(socket_in->remote_addr.sin_port));
                return size;
            }
            written = sendto(socket_in->socket, buffer, size, 0, (struct sockaddr*)&socket_in->remote_addr, sizeof(socket_in->remote_addr));
        }
        if (written < 0)
            perror("sendto");
    }
    free(buffer);
    return written;
}

#ifdef _WIN32
int waitIO(struct proxy_socket **sockets, socket_proxy_t proxy, int ms) {
    if ((!sockets) || (!(*sockets)))
        return 0;

    struct timeval timeout;
    struct timeval *ref_timeout = NULL;

    struct fd_set fds;
    timeout.tv_sec = ms / 1000;
    timeout.tv_usec = (ms % 1000) * 1000;

    FD_ZERO(&fds);
    int i = 0;
    while ((*sockets)[i].socket > 0) {
        FD_SET((*sockets)[i ++].socket, &fds);
    }
    if (ms > 0)
        ref_timeout = &timeout;
    if (select(0, &fds, 0, 0, ref_timeout)) {
        i = 0;
        while ((*sockets)[i].socket > 0) {
            if (FD_ISSET((*sockets)[i].socket, &fds)) {
                // may get realloc'ed
                struct proxy_socket ref_socket = (*sockets)[i];
                proxy(&ref_socket, sockets);
            }
            i ++;
        }

    }
    return 0;
}
#else
int waitIO(struct proxy_socket **sockets, socket_proxy_t proxy, int ms) {
    if ((!sockets) || (!*sockets))
        return 0;

    if (ms == 0)
        ms = -1;
    struct pollfd fds[1024];

    int fds_count = 0;
    int i;
    while ((*sockets)[fds_count].socket > 0) {
        fds[fds_count].fd = (*sockets)[fds_count].socket;
        fds[fds_count].events = POLLIN;
        fds_count++;

        if (fds_count >= 1024)
            break;
    }
    if (poll(fds, fds_count, ms) > 0) {
        for (i = 0; i < fds_count; i ++) {
            if (fds[i].revents & POLLIN) {
                // may get realloc'ed
                struct proxy_socket ref_socket = (*sockets)[i];
                proxy(&ref_socket, sockets);
            }
        }

    }
    return 0;
}
#endif

int main(int argc, char **argv) { 
    if ((argc != 9) && (argc != 7)) {
        printf("UDProxy v0.1 beta\nUnlicensed in 2023 by Eduard Suica\nUsage: %s <in_interface> <in_port> <source> <source_port> [<out_interface> <out_port>] <destination> <destination_port>\n", argv[0]);
        return -1;
    }
#ifdef _WIN32
    WORD wVersionRequested = MAKEWORD(2, 2);
    WSADATA wsaData;

    WSAStartup(wVersionRequested, &wsaData);
#endif

    struct sockaddr_in in_addr;
    int in_socket = createSocket(argv[1], atoi(argv[2]), &in_addr);
    if (in_socket <= 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }

    int out_socket;
    struct sockaddr_in out_addr = in_addr;
    if (argc == 9) {
        out_socket = createSocket(argv[5], atoi(argv[6]), &out_addr);
        if (out_socket <= 0) {
#ifdef _WIN32
            WSACleanup();
#endif
            return -1;
        }
    } else
        out_socket = in_socket;

    struct proxy_socket *sockets = (struct proxy_socket *)malloc(3 * sizeof(struct proxy_socket));
    memset(sockets, 0, 3 * sizeof(struct proxy_socket));

    time_t now = time(NULL);

    sockets[0].socket = in_socket;
    sockets[0].timestamp = now;
    sockets[0].is_sip = 1;
    sockets[0].socket_pair = 2;
    sockets[0].local_addr = in_addr;
    sockets[0].bind = 1;
    sockets[0].remote_mode = ALLOW_FIXED_DESTINATION;
    if (argc == 9)
        buildAddress(&sockets[0], argv[7], atoi(argv[8]));
    else
        buildAddress(&sockets[0], argv[5], atoi(argv[6]));

    sockets[1].socket = out_socket;
    sockets[1].timestamp = now;
    sockets[1].is_sip = 1;
    sockets[1].socket_pair = 1;
    sockets[1].local_addr = out_addr;
    sockets[1].bind = 1;
    sockets[1].remote_mode = ALLOW_FIXED_DESTINATION;

    buildAddress(&sockets[1], argv[3], atoi(argv[4]));

    while (1) {
        waitIO(&sockets, proxyIO, 10000);
        clearSockets(sockets, SOCKET_CLEAN_TIMEOUT, 0);
    }

    free(sockets);
 
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
