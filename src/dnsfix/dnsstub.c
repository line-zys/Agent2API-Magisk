/*
 * ag2a DNS 转发器（Android 专用，为 3.5.1+ 补上 127.0.0.1:53）
 *
 * 为什么要它：
 *   上游 3.5.1 起域名解析改成进程内 hickory resolver，只认 /etc/resolv.conf。
 *   Android 根分区 erofs 只读，没有这个文件，bind mount 也建不出目标，二进制里
 *   也没有任何硬编码 DNS 或 DNS 环境变量。此时 glibc 会回落到 127.0.0.1:53
 *   发查询（已抓包证实）。旧版网关自己解出 dnsproxy 应答，3.5.1 不再解了，
 *   所以由本程序顶上，否则所有出站请求都是 dns error。
 *
 * 行为：监听 127.0.0.1:53（UDP），转发给上游并发抢占，带 TTL 缓存。
 *       端口被占则打印一行日志退出，绝不抢端口。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_ADDR "127.0.0.1"
#define LISTEN_PORT 53
#define MAX_UP 4
#define MAX_PKT 4096
#define CACHE_SLOTS 256
#define CACHE_MAX_TTL 3600
#define QUERY_TIMEOUT_MS 4000

static struct sockaddr_in g_up[MAX_UP];
static int g_nup = 0;

typedef struct {
    uint8_t key[256];
    int keylen;
    uint8_t data[MAX_PKT];
    int len;
    time_t expire;
} cache_ent;

static cache_ent g_cache[CACHE_SLOTS];
static unsigned g_cache_rr = 0;

static void cache_key(const uint8_t *p, int n, uint8_t *out, int *outlen) {
    if (n <= 2) { *outlen = 0; return; }
    int m = n - 2;
    if (m > 256) m = 256;
    memcpy(out, p + 2, (size_t)m);
    *outlen = m;
}

static int cache_get(const uint8_t *key, int keylen, uint8_t *out, int *outlen) {
    if (keylen <= 0) return 0;
    time_t now = time(NULL);
    for (int i = 0; i < CACHE_SLOTS; i++) {
        cache_ent *e = &g_cache[i];
        if (e->keylen == keylen && e->len > 0 && memcmp(e->key, key, (size_t)keylen) == 0) {
            if (e->expire <= now) { e->len = 0; return 0; }
            memcpy(out, e->data, (size_t)e->len);
            *outlen = e->len;
            return 1;
        }
    }
    return 0;
}

static void cache_put(const uint8_t *key, int keylen, const uint8_t *data, int len, int ttl) {
    if (keylen <= 0 || len <= 0 || len > MAX_PKT) return;
    if (ttl < 5) ttl = 5;
    if (ttl > CACHE_MAX_TTL) ttl = CACHE_MAX_TTL;
    cache_ent *e = &g_cache[g_cache_rr++ % CACHE_SLOTS];
    memcpy(e->key, key, (size_t)keylen);
    e->keylen = keylen;
    memcpy(e->data, data, (size_t)len);
    e->len = len;
    e->expire = time(NULL) + ttl;
}

static int resp_ttl(const uint8_t *p, int n) {
    if (n < 12) return 60;
    int ancount = (p[6] << 8) | p[7];
    if (ancount <= 0) return 30;

    /* 跳过 question 段：QNAME(可能以 0 结尾，也可能是压缩指针) + QTYPE(2) + QCLASS(2) */
    int i = 12;
    if (i < n && (p[i] & 0xC0)) {
        i += 2;
    } else {
        while (i < n && p[i] != 0) i += p[i] + 1;
        i += 1;                                   /* 结尾的 0 */
    }
    i += 4;                                       /* QTYPE + QCLASS */
    if (i > n) return 60;

    int min = 0x7fffffff;
    for (int a = 0; a < ancount; a++) {
        if (i >= n) break;

        /* answer 的 NAME：压缩指针(2B) 或 完整域名 + 结尾 0 */
        if (p[i] & 0xC0) {
            i += 2;
        } else {
            while (i < n && p[i] != 0) i += p[i] + 1;
            i += 1;
        }
        if (i + 10 > n) break;                    /* TYPE(2) CLASS(2) TTL(4) RDLEN(2) */

        uint32_t ttl = ((uint32_t)p[i + 4] << 24) | ((uint32_t)p[i + 5] << 16) |
                       ((uint32_t)p[i + 6] << 8) | (uint32_t)p[i + 7];
        int rdlen = (p[i + 8] << 8) | p[i + 9];

        /* ⚠ rdlen 来自报文，最大 65535；必须按它跳完后立刻校验，否则 i 冲出 n
         *   后继续读，会把相邻内存当 TTL（实测能返回 65537 这类不可能的 값）。 */
        i += 10 + rdlen;
        if (i > n) break;

        if ((int)ttl < min) min = (int)ttl;
    }
    if (min == 0x7fffffff || min < 0) return 60;
    return min;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int resolve(const uint8_t *q, int qn, uint8_t *out, int *outn) {
    int fd[MAX_UP];
    for (int i = 0; i < MAX_UP; i++) fd[i] = -1;
    for (int i = 0; i < g_nup; i++) {
        fd[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd[i] < 0) continue;
        if (sendto(fd[i], q, (size_t)qn, 0, (struct sockaddr *)&g_up[i], sizeof(g_up[i])) < 0) {
            close(fd[i]);
            fd[i] = -1;
        }
    }
    uint64_t deadline = now_ms() + QUERY_TIMEOUT_MS;
    int got = 0;
    while (!got && now_ms() < deadline) {
        fd_set rs;
        FD_ZERO(&rs);
        int maxfd = -1;
        for (int i = 0; i < MAX_UP; i++) {
            if (fd[i] >= 0) { FD_SET(fd[i], &rs); if (fd[i] > maxfd) maxfd = fd[i]; }
        }
        if (maxfd < 0) break;
        struct timeval tv;
        uint64_t left = deadline - now_ms();
        tv.tv_sec = (time_t)(left / 1000);
        tv.tv_usec = (suseconds_t)((left % 1000) * 1000);
        int r = select(maxfd + 1, &rs, NULL, NULL, &tv);
        if (r <= 0) break;
        for (int i = 0; i < MAX_UP; i++) {
            if (fd[i] >= 0 && FD_ISSET(fd[i], &rs)) {
                int n = (int)recv(fd[i], out, MAX_PKT, 0);
                if (n > 12) { *outn = n; got = 1; }
                break;
            }
        }
    }
    for (int i = 0; i < MAX_UP; i++) if (fd[i] >= 0) close(fd[i]);
    return got;
}

static void load_upstreams(void) {
    FILE *f = fopen("/data/adb/ag2a/dnsfix/upstreams", "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f) && g_nup < MAX_UP) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '#' || *p == '\n' || *p == '\0') continue;
            if (strncmp(p, "nameserver", 10) == 0) {
                p += 10;
                while (*p == ' ' || *p == '\t') p++;
            }
            char *nl = strpbrk(p, " \t\r\n");
            if (nl) *nl = '\0';
            struct in_addr ia;
            if (inet_pton(AF_INET, p, &ia) == 1) {
                memset(&g_up[g_nup], 0, sizeof(g_up[g_nup]));
                g_up[g_nup].sin_family = AF_INET;
                g_up[g_nup].sin_port = htons(53);
                g_up[g_nup].sin_addr = ia;
                g_nup++;
            }
        }
        fclose(f);
    }
    if (g_nup == 0) {
        const char *def[] = { "223.5.5.5", "119.29.29.29" };
        for (int i = 0; i < 2; i++) {
            memset(&g_up[g_nup], 0, sizeof(g_up[g_nup]));
            g_up[g_nup].sin_family = AF_INET;
            g_up[g_nup].sin_port = htons(53);
            inet_pton(AF_INET, def[i], &g_up[g_nup].sin_addr);
            g_nup++;
        }
    }
}

static void on_signal(int sig) { (void)sig; _exit(0); }

int main(void) {
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGPIPE, SIG_IGN);

    load_upstreams();

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("[dnsstub] socket"); return 1; }
    /* ⚠ 千万不要设 SO_REUSEADDR：UDP 下它允许多个进程同时绑同一端口，
     * 于是两个 dnsstub 会各收到一部分查询、应答互相覆盖（实测复现）。
     * 不设它，第二个实例 bind 直接 EADDRINUSE，才能正确触发「让位退出」。 */

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    inet_pton(AF_INET, LISTEN_ADDR, &addr.sin_addr);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[dnsstub] 绑定 %s:53 失败（%s），已有人占用，退出\n",
                LISTEN_ADDR, strerror(errno));
        return 1;
    }

    char ups[128] = "";
    for (int i = 0; i < g_nup; i++) {
        char buf[32];
        inet_ntop(AF_INET, &g_up[i].sin_addr, buf, sizeof(buf));
        strncat(ups, buf, sizeof(ups) - strlen(ups) - 2);
        if (i + 1 < g_nup) strncat(ups, ",", sizeof(ups) - strlen(ups) - 1);
    }
    printf("[dnsstub] 监听 %s:53，上游 %s\n", LISTEN_ADDR, ups);
    fflush(stdout);

    static uint8_t q[MAX_PKT], r[MAX_PKT], key[256];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int n = (int)recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
        if (n <= 12) continue;

        int keylen = 0, rn = 0;
        cache_key(q, n, key, &keylen);

        if (cache_get(key, keylen, r, &rn)) {
            r[0] = q[0];
            r[1] = q[1];
        } else if (resolve(q, n, r, &rn)) {
            cache_put(key, keylen, r, rn, resp_ttl(r, rn));
        } else {
            continue;
        }
        sendto(fd, r, (size_t)rn, 0, (struct sockaddr *)&from, fl);
    }
    return 0;
}
