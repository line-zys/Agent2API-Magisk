#!/system/bin/sh
# dnsproxy 保活器：盯着网关的本地 DNS 代理（$WORK/dnsfix/dnsproxy，监听 127.0.0.1:53）。
#
# 为什么要有这个进程（26.11.12 以前的版本栽过的两个坑）：
#   网关和所有 glibc 二进制（网关本体、插件）在 Android 上没有 /etc/resolv.conf，
#   解析域名只剩 127.0.0.1:53 这一条路——也就是必须依赖 dnsproxy，没有第二条。
#   dnsproxy 是网关第一次用到时自己解出来的，但之后壳层没人管它：
#     ⚠ 解出来或被流程收成 0600（丢了执行位）⇒ execve 永远 EACCES，网关不重试；
#     ⚠ 被优雅停掉一次（网络切换、服务重启）⇒ 网关运行期间不会再拉。
#   两种死法同一种病：全进程组 DNS 瘫痪，上层只报「无法连接上游 / name resolution」，
#   夜里死了没人发现。26.11.12 起由本进程负责它的整个生命周期。
#
# 保活模型和 watchdog.sh 一致：起 → wait（阻塞系统调用）→ 死了退避重拉。
# dnsproxy 活着时本进程零 CPU，不轮询、不阻休眠。
#
# 端口礼仪：127.0.0.1:53 起来时已经有人在听（网关自己拉起来了、或 AdGuard 类本地
# DNS）就让位退出；自己拉的死掉后发现端口被别人占了，也体面收场，绝不抢端口。
#
# 用法：由 service.sh 管（start_dnsd / stop_dnsd，幂等）；手动跑：
#   sh /data/adb/modules/ag2a/dnsd.sh
# 上游配置：$WORK/dnsfix/upstreams 每行一条（如 udp://223.5.5.5:53、DoH URL），
# 原样作为 dnsproxy 的 -u 参数；没有该文件时用公共 DNS（见 lib.sh ag2a_dns_upstreams）。

MODDIR="$(dirname "$(readlink -f "$0")")"
. "$MODDIR/lib.sh"

WORK=$(ag2a_data_dir)
# 优先用模块自带的 dnsstub（3.5.1 起网关不再解 dnsproxy，只能自己提供 53 应答者）。
# 退回旧路径是为了兼容 3.5.0 及以前的网关（它们会自己解出 dnsproxy）。
STUB="$MODDIR/bin/dnsstub"
BIN="$WORK/dnsfix/dnsproxy"
if [ -x "$STUB" ]; then
    BIN="$STUB"
fi
PIDFILE="$WORK/dnsd.pid"
CPID="$WORK/dnsproxy.pid"
LOGF="$WORK/dnsfix/dnsproxy.log"
# 新代网关不再创建 dnsfix/（它已经不碰这个目录了），日志目录得自己建
mkdir -p "$WORK/dnsfix" 2>/dev/null

# ---------- 单实例 ----------
# pid 会被复用，必须校验 cmdline 里确实有 dnsd.sh
_old=$(cat "$PIDFILE" 2>/dev/null)
if [ -n "$_old" ] && [ "$_old" != "$$" ] && kill -0 "$_old" 2>/dev/null &&
   grep -q 'dnsd\.sh' "/proc/$_old/cmdline" 2>/dev/null; then
    exit 0
fi
echo "$$" > "$PIDFILE"

_dp=""
_sp=""

# ---------- 退出：先把 dnsproxy 带走，再清 pidfile ----------
_cleanup() {
    trap - TERM INT HUP
    [ -n "$_sp" ] && kill "$_sp" 2>/dev/null
    [ -n "$_dp" ] && kill "$_dp" 2>/dev/null
    rm -f "$PIDFILE" "$CPID" 2>/dev/null
    exit 0
}
trap '_cleanup' TERM INT HUP

_log() {
    echo "$(date '+%m-%d %H:%M:%S') [dnsd] $*" >> "$WORK/run.log" 2>/dev/null
}

# ---------- 等二进制就绪 ----------
# dnsstub 随模块发布，正常情况下立刻就在；只有退回旧代 dnsproxy 时才需要等网关解出来
# （网关在首次用到 dnsfix 时几秒内完成，一直不出 = 这版本不用它，最多等 10 分钟退出）。
ag2a_dns_fix_perms
chmod 755 "$STUB" 2>/dev/null
_i=0
while [ ! -x "$BIN" ] && [ "$_i" -lt 10 ]; do
    [ "$BIN" = "$STUB" ] && break      # 自带 stub 却不可执行 = 打包坏了，别空等
    sleep 60 &
    _sp=$!
    wait "$_sp"
    _sp=""
    _i=$((_i + 1))
    # 等待期间可能有人接了本进程的单（新的 dnsd 覆盖了 pidfile），让位退出
    [ "$(cat "$PIDFILE" 2>/dev/null)" = "$$" ] || exit 0
done
if [ ! -x "$BIN" ]; then
    _log "$BIN 一直没出现（网关没用 dnsfix），退出"
    rm -f "$PIDFILE" 2>/dev/null
    exit 0
fi

if ag2a_dns_listen; then
    _log "127.0.0.1:53 已在监听（网关自己拉的 / 其它 DNS 组件），不抢端口，退出"
    rm -f "$PIDFILE" 2>/dev/null
    exit 0
fi

_log "启动 (pid $$) upstreams:$(ag2a_dns_upstreams)"

_fails=0
while :; do
    # 执行位自愈：某些流程会把 dnsfix/ 下的文件收成 0600（见头注释），每轮起之前补一遍
    ag2a_dns_fix_perms
    chmod 755 "$STUB" 2>/dev/null
    # dnsstub 自己读 $WORK/dnsfix/upstreams、自己绑 127.0.0.1:53，无参数。
    # dnsproxy（旧代）需要 -l/-p/-u 那一套：词分割是故意的，
    # ag2a_dns_upstreams 只吐校验过的安全字符集。
    if [ "$BIN" = "$STUB" ]; then
        "$BIN" >> "$LOGF" 2>&1 &
    else
        # shellcheck disable=SC2046
        "$BIN" -l 127.0.0.1 -p 53 $(ag2a_dns_upstreams) --upstream-mode=parallel --cache >> "$LOGF" 2>&1 &
    fi
    _dp=$!
    echo "$_dp" > "$CPID" 2>/dev/null

    read -r _t0 _ < /proc/uptime
    _t0=${_t0%.*}

    wait "$_dp"
    _rc=$?
    _dp=""
    rm -f "$CPID" 2>/dev/null

    read -r _t1 _ < /proc/uptime
    _t1=${_t1%.*}
    _alive=$((_t1 - _t0))

    # 活够 60 秒算「正常运行后退出」，退避归零；秒退说明端口被占/文件坏了，拉长间隔
    if [ "$_alive" -ge 60 ]; then
        _fails=0
    else
        _fails=$((_fails + 1))
    fi

    # 秒退且 53 有人在听：是别人接管了端口，本保活器使命完成
    if [ "$_alive" -lt 10 ] && ag2a_dns_listen; then
        _log "dnsproxy 退出 rc=$_rc，53 已被其它进程接管，退出"
        rm -f "$PIDFILE" 2>/dev/null
        exit 0
    fi

    _log "dnsproxy 退出 rc=$_rc 存活 ${_alive}s，连续短命 ${_fails} 次后退避重拉"
    case "$_fails" in
        0) _wb=1 ;;
        1) _wb=2 ;;
        2) _wb=5 ;;
        3) _wb=10 ;;
        4) _wb=30 ;;
        *) _wb=60 ;;
    esac
    # 退避也要能被 stop 立刻打断，所以放后台再 wait
    sleep "$_wb" &
    _sp=$!
    wait "$_sp"
    _sp=""

    # 退避期间端口被别的人占了就让位，别再抢
    if ag2a_dns_listen; then
        _log "53 在退避期间被其它进程占用，退出"
        rm -f "$PIDFILE" 2>/dev/null
        exit 0
    fi
done
