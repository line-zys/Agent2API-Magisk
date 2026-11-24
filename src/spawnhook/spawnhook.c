/*
 * spawnhook - 让 glibc 插件在缺少 /lib/ld-linux-aarch64.so.1 的 Android 上跑起来
 *
 * 背景：插件是 glibc 二进制，ELF 里 PT_INTERP 写死 /lib/ld-linux-aarch64.so.1。
 *       Android 根目录没有 /lib（部分 ROM 直接删了），execve 返回 ENOENT。
 *       网关是 execve 直接拉起插件的，落盘即执行，中间没有可干预的时机。
 *
 * 做法：网关本身是用模块自带的 ld.so 拉起来的（service.sh 里那行 loader --library-path），
 *       所以给它带 --preload libspawnhook.so 即可拦截它所有 spawn 调用：
 *       发现目标 ELF 的解释器不存在、且就是 /lib/ld-linux-aarch64.so.1，
 *       就改成用模块自带的 loader 拉起同一个文件。
 *
 * 不改网关、不改插件、不动系统分区、不抢时间窗口 -> 网页内安装/升级全部零感知。
 *
 * 开关：存在 /data/adb/ag2a/spawnhook.off 时完全旁路（排障用）。
 *
 * 26.11.24_7 的修正：
 *   1) build_argv 的数组多留一格 —— argc==0（argv 为 NULL 或 argv[0] 为 NULL）时
 *      原写法 calloc(argc+4) 只有 4 槽，写完 4 项再写 NULL 就是堆外写 8 字节；
 *      网关是常驻多线程进程，堆块头被写坏后会在之后某次 malloc/free 时 abort。
 *   2) execve 劫持失败时保留 loader 的真实 errno，不再被「回落原路径」的 ENOENT
 *      覆盖 —— 以前排障只会看到 No such file or directory 指向插件文件，
 *      真正原因（loader 起不来）被彻底掩盖。
 *   3) execvp 自己按 PATH 搜索。以前直接转给 execve，等于把 PATH 搜索整段丢掉，
 *      任何 execvp("sh") 式的调用都会 ENOENT。
 *   4) real 函数指针在 constructor 里预先解析（网关是 tokio 多线程，惰性初始化的
 *      静态指针存在数据竞争）；wants_hijack 只对普通文件读、用 O_NONBLOCK 打开，
 *      避免路径被换成 FIFO 时卡住调用线程；ELF 头多校验字节序与 e_type。
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <spawn.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef AG2A_LOADER
#define AG2A_LOADER "/data/adb/modules/ag2a/lib/ld-linux-aarch64.so.1"
#endif
#ifndef AG2A_LIBDIR
#define AG2A_LIBDIR "/data/adb/modules/ag2a/lib"
#endif
#define AG2A_KILL_SWITCH "/data/adb/ag2a/spawnhook.off"

/* 插件 ELF 里写死的解释器；只有命中它才接管，bionic 程序（/system/bin 下的）
 * 一律不碰 */
static const char kWant[] = "/lib/ld-linux-aarch64.so.1";

typedef int (*spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                        const posix_spawnattr_t *, char *const[], char *const[]);
typedef int (*exec_fn)(const char *, char *const[], char *const[]);

static spawn_fn r_posix_spawn;
static spawn_fn r_posix_spawnp;
static exec_fn r_execve;

/* 预先解析，避免多线程下惰性初始化打架 */
__attribute__((constructor)) static void hook_init(void)
{
    r_posix_spawn = (spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
    r_posix_spawnp = (spawn_fn)dlsym(RTLD_NEXT, "posix_spawnp");
    r_execve = (exec_fn)dlsym(RTLD_NEXT, "execve");
}

static int disabled(void)
{
    return access(AG2A_KILL_SWITCH, F_OK) == 0;
}

/* 读 ELF 的 PT_INTERP，判断是不是需要接管。返回 1 = 需要。
 * 只对普通文件下手：路径被换成 FIFO 或设备文件时立刻返回，绝不阻塞调用线程。 */
static int wants_hijack(const char *path)
{
    if (!path || path[0] != '/')
        return 0;

    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return 0;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return 0;
    }

    unsigned char eh[sizeof(Elf64_Ehdr)];
    ssize_t n = read(fd, eh, sizeof eh);
    if (n != (ssize_t)sizeof eh || memcmp(eh, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return 0;
    }

    const Elf64_Ehdr *e = (const Elf64_Ehdr *)eh;
    if (e->e_ident[EI_CLASS] != ELFCLASS64 || e->e_ident[EI_DATA] != ELFDATA2LSB ||
        (e->e_type != ET_DYN && e->e_type != ET_EXEC) ||
        e->e_phoff == 0 || e->e_phnum == 0 ||
        e->e_phentsize != sizeof(Elf64_Phdr)) {
        close(fd);
        return 0;
    }

    int hit = 0;
    for (int i = 0; i < e->e_phnum; i++) {
        Elf64_Phdr ph;
        if (pread(fd, &ph, sizeof ph, (off_t)(e->e_phoff + (off_t)i * sizeof ph)) !=
            (ssize_t)sizeof ph)
            break;
        if (ph.p_type != PT_INTERP || ph.p_filesz == 0 || ph.p_filesz > 256)
            continue;
        char buf[257];
        if (pread(fd, buf, ph.p_filesz, (off_t)ph.p_offset) != (ssize_t)ph.p_filesz)
            break;
        buf[ph.p_filesz] = '\0';
        if (strcmp(buf, kWant) == 0)
            hit = 1;
        break;
    }
    close(fd);
    return hit;
}

/* 需要接管就返回 1，并给出新的 argv（调用方负责 free） */
static int build_argv(const char *path, char *const argv[], char *const envp[], char ***out)
{
    (void)envp;
    if (disabled() || !wants_hijack(path))
        return 0;
    /* 解释器已经能直接找到就没必要插手（例如别家 ROM 有 /lib） */
    if (access(kWant, X_OK) == 0)
        return 0;
    if (access(AG2A_LOADER, X_OK) != 0)
        return 0;

    int argc = 0;
    if (argv)
        while (argv[argc])
            argc++;

    /* [loader, --library-path, libdir, 原路径, 原 argv[1..], NULL]
     * 多留一格：argc==0 时上面的循环不跑，4 项之后还要写 NULL，正好用满第 5 格 */
    char **na = (char **)calloc((size_t)argc + 5, sizeof(char *));
    if (!na)
        return 0;
    int k = 0;
    na[k++] = (char *)AG2A_LOADER;
    na[k++] = (char *)"--library-path";
    na[k++] = (char *)AG2A_LIBDIR;
    na[k++] = (char *)path;
    for (int i = 1; i < argc; i++)
        na[k++] = argv[i];
    na[k] = NULL;
    *out = na;
    return 1;
}

/* loader 起不来时把真因写一行到 stderr（只写一次，避免刷屏），
 * 然后带着这个 errno 返回 —— 不再用原路径的 ENOENT 覆盖它。 */
static void report_loader_fail(const char *path, int e)
{
    static int warned;
    if (warned)
        return;
    warned = 1;
    char m[512];
    int n = snprintf(m, sizeof m,
                     "[spawnhook] %s 用模块自带的 loader 拉起失败：%s；"
                     "插件无法启动（检查模块 lib/ 是否完整）\n",
                     path, strerror(e));
    if (n > 0)
        (void)write(STDERR_FILENO, m, (size_t)((n < (int)sizeof m) ? n : (int)sizeof m - 1));
}

int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *attr, char *const argv[], char *const envp[])
{
    spawn_fn real = r_posix_spawn ? r_posix_spawn : (spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
    int saved = errno;
    if (!real) {
        errno = saved;
        return -1;
    }
    char **na = NULL;
    if (build_argv(path, argv, envp, &na)) {
        int rc = real(pid, AG2A_LOADER, fa, attr, na, envp);
        if (rc != 0)
            report_loader_fail(path, rc);
        free(na);
        errno = saved;                 /* posix_spawn 用返回值报错，不动 errno */
        return rc;
    }
    errno = saved;
    return real(pid, path, fa, attr, argv, envp);
}

int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *attr, char *const argv[], char *const envp[])
{
    spawn_fn real = r_posix_spawnp ? r_posix_spawnp : (spawn_fn)dlsym(RTLD_NEXT, "posix_spawnp");
    int saved = errno;
    if (!real) {
        errno = saved;
        return -1;
    }
    char **na = NULL;
    if (build_argv(file, argv, envp, &na)) {
        int rc = real(pid, AG2A_LOADER, fa, attr, na, envp);
        if (rc != 0)
            report_loader_fail(file, rc);
        free(na);
        errno = saved;
        return rc;
    }
    errno = saved;
    return real(pid, file, fa, attr, argv, envp);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    exec_fn real = r_execve ? r_execve : (exec_fn)dlsym(RTLD_NEXT, "execve");
    int saved = errno;
    if (!real) {
        errno = saved;
        return -1;
    }
    char **na = NULL;
    if (build_argv(path, argv, envp, &na)) {
        real(AG2A_LOADER, na, envp);
        int e = errno;                 /* loader 的真实错误，必须留住 */
        free(na);
        report_loader_fail(path, e);
        errno = e;
        return -1;
    }
    errno = saved;
    return real(path, argv, envp);
}

int execv(const char *path, char *const argv[])
{
    extern char **environ;
    return execve(path, argv, environ);
}

/* 以前这里直接转给 execve，等于把 PATH 搜索丢掉了。自己搜一遍。 */
int execvp(const char *file, char *const argv[])
{
    extern char **environ;
    if (!file || !*file) {
        errno = ENOENT;
        return -1;
    }
    if (strchr(file, '/'))
        return execve(file, argv, environ);

    const char *p = getenv("PATH");
    if (!p || !*p)
        p = "/system/bin:/system/xbin:/data/adb/ksu/bin:/data/adb/magisk:"
            "/data/adb/ap/bin:/vendor/bin:/sbin:/bin:/usr/bin";
    size_t fl = strlen(file);
    int saw_eacces = 0;
    while (*p) {
        const char *e = strchr(p, ':');
        size_t dl = e ? (size_t)(e - p) : strlen(p);
        if (dl > 0 && dl + 1 + fl < 4090) {
            char buf[4096];
            memcpy(buf, p, dl);
            buf[dl] = '/';
            memcpy(buf + dl + 1, file, fl + 1);
            execve(buf, argv, environ);
            if (errno == EACCES)
                saw_eacces = 1;
        }
        if (!e)
            break;
        p = e + 1;
    }
    errno = saw_eacces ? EACCES : ENOENT;
    return -1;
}
