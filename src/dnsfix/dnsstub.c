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
 * 行为：监听 127.0.0.1:53（UDP + TCP），转发给上游抢答，带 TTL 缓存。
 *       端口被占则打印一行日志退出，绝不抢端口。
 *
 * 26.11.24_7 的修正（都是踩过的坑，别再改回去）：
 *   1) 补 TCP 监听。没有它，客户端（glibc 的插件就是）收到 TC=1 会改走 TCP 重问，
 *      53/tcp 无人应答 ⇒ ECONNREFUSED ⇒ 解析失败，且报错与原来的 dns error 一样，
 *      排障会被带偏。TCP 路径不做 512 字节截断。
 *   2) 给转发查询注入 EDNS0（bufsize=1232）。客户端（glibc 默认）不带 EDNS0 时
 *      上游只肯回 512 字节并置 TC；注入后上游才肯给完整应答，再由我们决定
 *      给这个客户端截断、还是让它走 TCP。
 *   3) 应答校验：源地址必须是发过查询的那台上游、事务 ID 相同、QR=1，否则丢弃
 *      继续等。以前直接 recv() 收第一包，本机任意进程都能往缓存里投毒。
 *   4) recvfrom 带 MSG_TRUNC 取真实长度，超长报文丢弃，不再让内核静默截断后
 *      当成完整答案转发 + 缓存。
 *   5) 每个查询一个线程（上限 MAX_WORKERS）：以前一次 miss 串行阻塞 4 秒，期间
 *      所有查询在内核队列里排队到丢包，表现为随机 dns error。
 *   6) 缓存：key 存查询原文做 memcmp（哈希碰撞不再串答案）、单调钟记过期、命中时
 *      把应答 TTL 递减成剩余值、rcode!=0 只缓存 1 秒。
 *   7) resp_ttl 按 QDCOUNT 跳过 question 段、校验标签长度（1..63），不再把相邻
 *      内存当 TTL 读。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
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

/* 这几个常量用 #ifndef 包起来：本地跑功能自测时可以用 -DLISTEN_PORT=… 换端口，
 * 免得测试环境里跟系统 DNS 抢 53。生产构建不传这些宏，行为与写死完全一致。 */
#ifndef LISTEN_ADDR
#define LISTEN_ADDR "127.0.0.1"
#endif
#ifndef LISTEN_PORT
#define LISTEN_PORT 53
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
#define MAX_UP 4
#define UDP_MAX 4096             /* 回给 UDP 客户端的上限 */
#define TCP_MAX 8192             /* TCP 客户端可更大（无 512 限制） */
#define CACHE_SLOTS 256
#define CACHE_MAX_TTL 3600
#define QUERY_TIMEOUT_MS 2500    /* 上游抢答窗口 */
#define EDNS_SIZE 1232
#define MAX_WORKERS 32
#define QKEY_MAX 512             /* 超长查询不进缓存（极罕见） */
#define UPSTREAMS_ENV "AG2A_DNS_UPSTREAMS"
#define UPSTREAMS_FILE "/data/adb/ag2a/dnsfix/upstreams"

static struct sockaddr_in g_up[MAX_UP];
static int g_nup = 0;
static int g_udp_fd = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_workers = 0;

typedef struct {
    int used;
    uint64_t hash;
    int qlen;
    int len;
    int ttl;
    uint64_t expire_ms;          /* CLOCK_MONOTONIC 毫秒：墙钟跳变不影响缓存 */
    uint8_t qkey[QKEY_MAX];
    uint8_t data[UDP_MAX];
} cache_ent;

static cache_ent g_cache[CACHE_SLOTS];
static unsigned g_cache_rr = 0;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* FNV-1a 64：整段查询去掉事务 ID。哈希只用于找槽，命中还要 memcmp 原文。 */
static uint64_t hash_query(const uint8_t *p, int n) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 2; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    h ^= (uint64_t)n;
    return h;
}

/* 跳过 NAME（标签或压缩指针），返回下一字段偏移；格式非法返回 -1。
 * ⚠ 标签长度必须校验：0x40~0xBF 是扩展标签、0xFF 越界，一次 i += p[i]+1
 *   能跳 255 字节，后面的 RR 会被错位当成 TTL 读。 */
static int skip_name(const uint8_t *p, int n, int i) {
    for (int guard = 0; guard < 128; guard++) {
        if (i >= n) return -1;
        uint8_t l = p[i];
        if (l == 0) return i + 1;
        if ((l & 0xC0) == 0xC0) return (i + 2 <= n) ? i + 2 : -1;
        if (l > 63) return -1;
        i += 1 + (int)l;
    }
    return -1;
}

/* question 段结束位置（第一个 RR 的起点）；QDCOUNT==0 时就是 12。 */
static int question_end(const uint8_t *p, int n) {
    if (n < 12) return -1;
    int qd = (p[4] << 8) | p[5];
    int i = 12;
    for (int k = 0; k < qd; k++) {
        i = skip_name(p, n, i);
        if (i < 0) return -1;
        if (i + 4 > n) return -1;
        i += 4;                                  /* QTYPE + QCLASS */
    }
    return i;
}

/* OPT（EDNS0）RR 的 TYPE 字段偏移；没有返回 -1。 */
static int find_opt(const uint8_t *p, int n) {
    int qend = question_end(p, n);
    if (qend < 0) return -1;
    int an = (p[6] << 8) | p[7];
    int ns = (p[8] << 8) | p[9];
    int ar = (p[10] << 8) | p[11];
    int i = qend;
    for (int k = 0; k < an + ns; k++) {
        i = skip_name(p, n, i);
        if (i < 0 || i + 10 > n) return -1;
        int rdlen = (p[i + 8] << 8) | p[i + 9];
        i += 10 + rdlen;
        if (i > n) return -1;
    }
    for (int k = 0; k < ar; k++) {
        i = skip_name(p, n, i);
        if (i < 0 || i + 10 > n) return -1;
        int type = (p[i] << 8) | p[i + 1];
        int rdlen = (p[i + 8] << 8) | p[i + 9];
        if (type == 41) return i;
        i += 10 + rdlen;
        if (i > n) return -1;
    }
    return -1;
}

/* 客户端查询 → 发往上游的查询：没有 OPT 就补一个（bufsize=1232），有但太小就抬高。
 * 返回 1 = 客户端本来就带 EDNS0，0 = 我们补的。 */
static int prepare_query(const uint8_t *q, int qn, uint8_t *out, int *outn, int cap) {
    if (qn < 12 || qn > cap) return -1;
    memcpy(out, q, (size_t)qn);
    int opt = find_opt(q, qn);
    if (opt >= 0) {
        int cls = (out[opt + 2] << 8) | out[opt + 3];
        if (cls < EDNS_SIZE) {
            out[opt + 2] = (uint8_t)(EDNS_SIZE >> 8);
            out[opt + 3] = (uint8_t)(EDNS_SIZE & 0xFF);
        }
        *outn = qn;
        return 1;
    }
    if (qn + 11 > cap) {                          /* 放不下就原样发 */
        *outn = qn;
        return 0;
    }
    uint8_t *e = out + qn;
    e[0] = 0x00;                                  /* NAME = root */
    e[1] = 0x00; e[2] = 0x29;                     /* TYPE = OPT(41) */
    e[3] = (uint8_t)(EDNS_SIZE >> 8);             /* CLASS = UDP payload size */
    e[4] = (uint8_t)(EDNS_SIZE & 0xFF);
    e[5] = e[6] = e[7] = e[8] = 0x00;             /* TTL = 0（无 DO 位） */
    e[9] = e[10] = 0x00;                          /* RDLEN = 0 */
    int ar = (out[10] << 8) | out[11];
    ar++;
    out[10] = (uint8_t)(ar >> 8);
    out[11] = (uint8_t)(ar & 0xFF);
    *outn = qn + 11;
    return 0;
}

/* answer 段最小 TTL；解析不出来返回 -1。 */
static int resp_min_ttl(const uint8_t *p, int n, int qend) {
    if (qend < 0 || qend > n || n < 12) return -1;
    int an = (p[6] << 8) | p[7];
    if (an <= 0) return -1;
    int i = qend;
    int min = 0x7fffffff;
    for (int a = 0; a < an; a++) {
        i = skip_name(p, n, i);
        if (i < 0 || i + 10 > n) break;
        uint32_t ttl = ((uint32_t)p[i + 4] << 24) | ((uint32_t)p[i + 5] << 16) |
                       ((uint32_t)p[i + 6] << 8) | (uint32_t)p[i + 7];
        int rdlen = (p[i + 8] << 8) | p[i + 9];
        i += 10 + rdlen;
        if (i > n) break;
        if ((int)ttl < min) min = (int)ttl;
    }
    if (min == 0x7fffffff) return -1;
    return min < 0 ? 0 : min;
}

/* 把各 answer 的 TTL 改写成 ttl（命中缓存时递减用）。解析异常就整体放弃。 */
static void set_answer_ttls(uint8_t *p, int n, int qend, int ttl) {
    if (qend < 0 || qend > n || n < 12 || ttl < 0) return;
    int an = (p[6] << 8) | p[7];
    int i = qend;
    for (int a = 0; a < an; a++) {
        i = skip_name(p, n, i);
        if (i < 0 || i + 10 > n) return;
        int rdlen = (p[i + 8] << 8) | p[i + 9];
        p[i + 4] = (uint8_t)((ttl >> 24) & 0xFF);
        p[i + 5] = (uint8_t)((ttl >> 16) & 0xFF);
        p[i + 6] = (uint8_t)((ttl >> 8) & 0xFF);
        p[i + 7] = (uint8_t)(ttl & 0xFF);
        i += 10 + rdlen;
        if (i > n) return;
    }
}

static int cache_get(uint64_t hash, const uint8_t *key, int keylen,
                     uint8_t *out, int *outlen, int *remain) {
    int hit = 0;
    uint64_t mono = now_ms();
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < CACHE_SLOTS; i++) {
        cache_ent *e = &g_cache[i];
        if (!e->used || e->hash != hash || e->qlen != keylen || e->len <= 0) continue;
        if (keylen > QKEY_MAX || memcmp(e->qkey, key, (size_t)keylen) != 0) continue;
        if (e->expire_ms <= mono) { e->used = 0; break; }
        memcpy(out, e->data, (size_t)e->len);
        *outlen = e->len;
        int r = (int)((e->expire_ms - mono) / 1000ULL);
        if (r < 1) r = 1;
        if (r > e->ttl) r = e->ttl;
        *remain = r;
        hit = 1;
        break;
    }
    pthread_mutex_unlock(&g_lock);
    return hit;
}

static void cache_put(uint64_t hash, const uint8_t *key, int keylen,
                      const uint8_t *data, int len, int ttl) {
    if (keylen <= 0 || keylen > QKEY_MAX || len <= 0 || len > UDP_MAX) return;
    if (ttl < 5) ttl = 5;
    if (ttl > CACHE_MAX_TTL) ttl = CACHE_MAX_TTL;
    pthread_mutex_lock(&g_lock);
    cache_ent *e = &g_cache[g_cache_rr++ % CACHE_SLOTS];
    e->hash = hash;
    e->qlen = keylen;
    memcpy(e->qkey, key, (size_t)keylen);
    memcpy(e->data, data, (size_t)len);
    e->len = len;
    e->ttl = ttl;
    e->expire_ms = now_ms() + (uint64_t)ttl * 1000ULL;
    e->used = 1;
    pthread_mutex_unlock(&g_lock);
}

/* 上游抢答：源地址必须是发过查询的那台 + 事务 ID 相同 + QR=1。 */
static int resolve(const uint8_t *q, int qn, uint8_t *out, int cap, int *outn) {
    int fd[MAX_UP];
    int nsent = 0;
    for (int i = 0; i < MAX_UP; i++) fd[i] = -1;
    for (int i = 0; i < g_nup; i++) {
        fd[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd[i] < 0) continue;
        if (sendto(fd[i], q, (size_t)qn, 0, (struct sockaddr *)&g_up[i], sizeof(g_up[i])) < 0) {
            close(fd[i]);
            fd[i] = -1;
            continue;
        }
        nsent++;
    }
    if (nsent == 0) return -1;

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
        uint64_t left = deadline - now_ms();
        struct timeval tv;
        tv.tv_sec = (time_t)(left / 1000);
        tv.tv_usec = (suseconds_t)((left % 1000) * 1000);
        int r = select(maxfd + 1, &rs, NULL, NULL, &tv);
        if (r <= 0) break;
        for (int i = 0; i < MAX_UP; i++) {
            if (fd[i] < 0 || !FD_ISSET(fd[i], &rs)) continue;
            struct sockaddr_in src;
            socklen_t sl = sizeof(src);
            int n = (int)recvfrom(fd[i], out, (size_t)cap, MSG_TRUNC,
                                  (struct sockaddr *)&src, &sl);
            if (n < 12 || n > cap) continue;                    /* 超长/过短都丢 */
            if (src.sin_addr.s_addr != g_up[i].sin_addr.s_addr) continue;
            if (out[0] != q[0] || out[1] != q[1]) continue;
            if ((out[2] & 0x80) == 0) continue;
            *outn = n;
            got = 1;
            break;
        }
    }
    for (int i = 0; i < MAX_UP; i++) if (fd[i] >= 0) close(fd[i]);
    return got ? 0 : -1;
}

/* 超时/无上游时回 SERVFAIL，比静默丢掉好排障。 */
static int build_servfail(const uint8_t *q, int qn, uint8_t *out, int cap) {
    if (qn < 12 || cap < 12) return -1;
    int qend = question_end(q, qn);
    if (qend < 0 || qend > cap) qend = 12;
    memcpy(out, q, (size_t)qend);
    out[2] = (uint8_t)(out[2] | 0x80);            /* QR = 1 */
    out[3] = (uint8_t)((out[3] & 0xF0) | 0x02);   /* RCODE = SERVFAIL */
    out[6] = 0; out[7] = 0;
    out[8] = 0; out[9] = 0;
    out[10] = 0; out[11] = 0;
    return qend;
}

/* 按 512 字节规则截断：只留 header + question，置 TC=1，让客户端走 TCP。 */
static int truncate_tc(uint8_t *buf, int len, int qend) {
    if (qend <= 0 || qend > len) return len;
    buf[2] = (uint8_t)(buf[2] | 0x02);            /* TC = 1 */
    buf[6] = 0; buf[7] = 0;
    buf[8] = 0; buf[9] = 0;
    buf[10] = 0; buf[11] = 0;
    return qend;
}

/* 核心：给一个客户端查询算出应答，返回长度；-1 无法应答。 */
static int answer(const uint8_t *q, int qn, uint8_t *out, int cap, int is_tcp,
                  int *client_edns) {
    uint8_t uq[UDP_MAX];
    int uqn = 0;
    if (qn < 12) return -1;
    int ce = prepare_query(q, qn, uq, &uqn, (int)sizeof(uq));
    if (ce < 0) return -1;
    if (client_edns) *client_edns = ce;

    uint64_t h = hash_query(uq, uqn);
    int len = 0;
    int remain = 0;
    int cached = cache_get(h, uq, uqn, out, &len, &remain);
    if (cached) {
        int qend = question_end(out, len);
        if (qend > 0) set_answer_ttls(out, len, qend, remain);
    } else {
        int rn = 0;
        if (resolve(uq, uqn, out, cap, &rn) != 0) {
            return build_servfail(q, qn, out, cap);
        }
        len = rn;
        int qend = question_end(out, len);
        int ttl = qend > 0 ? resp_min_ttl(out, len, qend) : -1;
        int rcode = out[3] & 0x0F;
        if (rcode != 0) ttl = 1;                  /* 失败应答别缓存 30 秒放大抖动 */
        else if (ttl < 0) ttl = 60;
        if (ttl >= 0) cache_put(h, uq, uqn, out, len, ttl);
    }
    out[0] = q[0];                                /* 事务 ID 归客户端 */
    out[1] = q[1];
    if (!is_tcp && ce == 0 && len > 512) {
        int qec = question_end(q, qn);
        if (qec > 0) len = truncate_tc(out, len, qec);
    }
    return len;
}

/* ---------------- 线程池 ---------------- */

typedef struct {
    int kind;                                     /* 0 = UDP, 1 = TCP */
    int qn;
    int conn;
    struct sockaddr_in from;
    uint8_t q[UDP_MAX];
} job;

static void *worker(void *arg) {
    job *j = (job *)arg;
    uint8_t *buf = (uint8_t *)malloc(TCP_MAX);
    if (!buf) {
        if (j->kind == 1) close(j->conn);
    } else if (j->kind == 0) {
        int len = answer(j->q, j->qn, buf, UDP_MAX, 0, NULL);
        if (len > 0) {
            sendto(g_udp_fd, buf, (size_t)len, 0,
                   (struct sockaddr *)&j->from, sizeof(j->from));
        }
    } else {
        uint8_t hdr[2];
        int n = 0;
        while (n < 2) {
            int r = (int)read(j->conn, hdr + n, (size_t)(2 - n));
            if (r <= 0) break;
            n += r;
        }
        if (n == 2) {
            int qlen = (hdr[0] << 8) | hdr[1];
            if (qlen > 12 && qlen <= UDP_MAX) {
                int got = 0;
                while (got < qlen) {
                    int r = (int)read(j->conn, j->q + got, (size_t)(qlen - got));
                    if (r <= 0) break;
                    got += r;
                }
                if (got == qlen) {
                    int len = answer(j->q, qlen, buf, TCP_MAX, 1, NULL);
                    if (len > 12) {
                        uint8_t ol[2];
                        ol[0] = (uint8_t)(len >> 8);
                        ol[1] = (uint8_t)(len & 0xFF);
                        (void)write(j->conn, ol, 2);
                        (void)write(j->conn, buf, (size_t)len);
                    }
                }
            }
        }
        close(j->conn);
    }
    free(buf);
    free(j);
    pthread_mutex_lock(&g_lock);
    g_workers--;
    pthread_mutex_unlock(&g_lock);
    return NULL;
}

static void spawn_job(job *j) {
    pthread_mutex_lock(&g_lock);
    if (g_workers >= MAX_WORKERS) {
        pthread_mutex_unlock(&g_lock);
        if (j->kind == 1) close(j->conn);
        free(j);
        return;
    }
    g_workers++;
    pthread_mutex_unlock(&g_lock);
    pthread_t th;
    if (pthread_create(&th, NULL, worker, j) != 0) {
        pthread_mutex_lock(&g_lock);
        g_workers--;
        pthread_mutex_unlock(&g_lock);
        if (j->kind == 1) close(j->conn);
        free(j);
        return;
    }
    pthread_detach(th);
}

/* ---------------- 启动 ---------------- */

static void load_upstreams(void) {
    const char *envf = getenv(UPSTREAMS_ENV);
    const char *path = (envf && *envf) ? envf : UPSTREAMS_FILE;
    FILE *f = fopen(path, "r");
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
                g_up[g_nup].sin_port = htons(UPSTREAM_PORT);
                g_up[g_nup].sin_addr = ia;
                g_nup++;
            }
        }
        fclose(f);
    }
    if (g_nup == 0) {
        const char *def[2] = { "223.5.5.5", "119.29.29.29" };
        for (int i = 0; i < 2; i++) {
            memset(&g_up[g_nup], 0, sizeof(g_up[g_nup]));
            g_up[g_nup].sin_family = AF_INET;
            g_up[g_nup].sin_port = htons(UPSTREAM_PORT);
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

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTEN_PORT);
    inet_pton(AF_INET, LISTEN_ADDR, &addr.sin_addr);

    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_fd < 0) { perror("[dnsstub] socket"); return 1; }
    /* ⚠ 不要设 SO_REUSEADDR：UDP 下它允许多个进程同绑一个端口，两个 dnsstub 会
     *   各收一部分查询、应答互相覆盖（实测复现）。不设它，第二个实例 bind 直接
     *   EADDRINUSE，才能正确触发「让位退出」。 */
    if (bind(g_udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[dnsstub] 绑定 %s:%d/udp 失败（%s），已有人占用，退出\n",
                LISTEN_ADDR, LISTEN_PORT, strerror(errno));
        return 1;
    }

    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd >= 0) {
        if (bind(tcp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
            listen(tcp_fd, 16) < 0) {
            fprintf(stderr, "[dnsstub] TCP %d 不可用（%s），只提供 UDP\n",
                    LISTEN_PORT, strerror(errno));
            close(tcp_fd);
            tcp_fd = -1;
        }
    }

    char ups[160] = "";
    for (int i = 0; i < g_nup; i++) {
        char buf[32];
        inet_ntop(AF_INET, &g_up[i].sin_addr, buf, sizeof(buf));
        size_t used = strlen(ups);
        if (used + strlen(buf) + 2 < sizeof(ups)) {
            if (used) strncat(ups, ",", sizeof(ups) - used - 1);
            strncat(ups, buf, sizeof(ups) - strlen(ups) - 1);
        }
    }
    printf("[dnsstub] 监听 %s:%d（udp%s），上游 %s\n", LISTEN_ADDR, LISTEN_PORT,
           tcp_fd >= 0 ? "+tcp" : "", ups);
    fflush(stdout);

    for (;;) {
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(g_udp_fd, &rs);
        int maxfd = g_udp_fd;
        if (tcp_fd >= 0) { FD_SET(tcp_fd, &rs); if (tcp_fd > maxfd) maxfd = tcp_fd; }
        int r = select(maxfd + 1, &rs, NULL, NULL, NULL);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (tcp_fd >= 0 && FD_ISSET(tcp_fd, &rs)) {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            int conn = accept(tcp_fd, (struct sockaddr *)&from, &fl);
            if (conn >= 0) {
                struct timeval tv;
                tv.tv_sec = 5; tv.tv_usec = 0;
                setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(conn, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                job *j = (job *)calloc(1, sizeof(job));
                if (!j) close(conn);
                else { j->kind = 1; j->conn = conn; spawn_job(j); }
            }
        }
        if (FD_ISSET(g_udp_fd, &rs)) {
            uint8_t q[UDP_MAX];
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            int n = (int)recvfrom(g_udp_fd, q, sizeof(q), MSG_TRUNC,
                                  (struct sockaddr *)&from, &fl);
            if (n < 12 || n > (int)sizeof(q)) continue;
            job *j = (job *)calloc(1, sizeof(job));
            if (!j) continue;
            j->kind = 0;
            j->qn = n;
            j->from = from;
            memcpy(j->q, q, (size_t)n);
            spawn_job(j);
        }
    }
    return 0;
}
