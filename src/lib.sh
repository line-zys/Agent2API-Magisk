#!/system/bin/sh
# 公共工具：control.sh / action.sh / service.sh / customize.sh 都会 source 它。
# 被 source 不执行，所以不需要可执行位。

# ---------- 路径 ----------
# MODDIR 由调用方设置（customize.sh 里是 $MODPATH，其余由 $0 推导）
DATA_DIR_DEFAULT=/data/adb/ag2a

# busybox 位置：Magisk / KernelSU / APatch 三种根方案各不相同。
# ⛔ 别只写死 /data/adb/magisk/busybox —— 本机是 APatch，只装了 /data/adb/ap/bin/busybox。
# 只在 source 时做几次 stat，不 fork。
AG2A_BUSYBOX=""
for _bb in /data/adb/ap/bin/busybox /data/adb/magisk/busybox /data/adb/ksu/bin/busybox; do
    [ -x "$_bb" ] && { AG2A_BUSYBOX=$_bb; break; }
done

# 数据目录：只认 /data/adb/ag2a（及其子目录）。
# ⛔ 这个值会被 rm -rf 用，绝不能由外部随意指定 —— 一旦变成空/根目录就是灾难。
# 本地测试用环境变量 AG2A_DATA_DIR 旁路（只在测试脚本里设）。
ag2a_data_dir() {
    if [ -n "$AG2A_DATA_DIR" ]; then
        echo "$AG2A_DATA_DIR"
        return
    fi
    _d=$(cat "$MODDIR/.datadir" 2>/dev/null | head -n1 | tr -d '\r')
    case "$_d" in
        /data/adb/ag2a | /data/adb/ag2a/*) : ;;
        *) _d=$DATA_DIR_DEFAULT ;;
    esac
    echo "$_d"
}

# ---------- 二进制 / 库 ----------
AG2A_ID=ag2a
AG2A_BIN_NAME=agent2api-server
AG2A_LD_NAME=ld-linux-aarch64.so.1
AG2A_HOOK_LIB=libspawnhook.so

# 运行体（bin/ + ui/）的权威位置＝数据目录下的 rt/。
# 为什么不用模块目录：/data/adb/modules/ag2a 是 Magisk 的地盘，只有**下次启动**才会被
#   modules_update 整体替换；运行体放里面，刷完 zip 不重启就还是旧二进制。
#   /data/adb/ag2a 是模块自己的数据，Magisk 从不碰 ⇒ 同步过去立刻生效。
# 同步逻辑在 rt.sh，这里只做路径解析。
ag2a_rt() { echo "$(ag2a_data_dir)/rt"; }

# 二进制：rt 优先，缺失时回退模块目录（保证任何情况下都起得来）
ag2a_bin() {
    _ab="$(ag2a_data_dir)/rt/bin/$AG2A_BIN_NAME"
    if [ -f "$_ab" ]; then echo "$_ab"; else echo "$MODDIR/bin/$AG2A_BIN_NAME"; fi
}

# UI 目录：同规则
ag2a_ui() {
    _au="$(ag2a_data_dir)/rt/ui"
    if [ -d "$_au" ]; then echo "$_au"; else echo "$MODDIR/ui"; fi
}

# rt 的版本戳（= 同步时源 module.prop 的 versionCode）。rt.sh sync 的最后一步才写它，
# 所以它等价于「这次同步完整跑完了」的提交点。读不到一律当 0（= 不可信，需要重同步）。
ag2a_rtver() {
    _rv=$(sed -n '1p' "$(ag2a_rt)/.rtver" 2>/dev/null | tr -dc '0-9')
    case "$_rv" in '' | *[!0-9]*) _rv=0 ;; esac
    echo "$_rv"
}

# 模块自带 module.prop 的 versionCode；读不到当 0
ag2a_modver() {
    _mv=$(sed -n 's/^versionCode=//p' "$MODDIR/module.prop" 2>/dev/null | head -n1 | tr -dc '0-9')
    case "$_mv" in '' | *[!0-9]*) _mv=0 ;; esac
    echo "$_mv"
}

# 是否需要把模块目录的 bin/ui 重新同步进 rt（0=需要 1=不需要）。
# 三种情况要同步：rt 里没有二进制 / 没有版本戳（同步被打断过） / rt 比模块旧。
# ⚠ 判据必须是「rt 比模块旧」而不是「不相等」：刷完 zip 但还没重启时，
#   rt 已经是新版、模块目录还是旧版，用「不相等」会把 rt 反而降级回旧版。
ag2a_rt_need_sync() {
    [ -f "$(ag2a_rt)/bin/$AG2A_BIN_NAME" ] || return 0
    _nsv=$(ag2a_rtver)
    [ "$_nsv" -gt 0 ] 2>/dev/null || return 0
    _nmv=$(ag2a_modver)
    [ "$_nmv" -gt "$_nsv" ] 2>/dev/null || return 1
    return 0
}

# 插件 spawn 拦截：插件是 glibc 二进制，ELF 里 PT_INTERP 写死 /lib/ld-linux-aarch64.so.1，
# 而 Android 根目录没有 /lib（有的 ROM 直接删了），execve 返回 ENOENT —— 插件装完起不来。
# 网关本来就是我们用 loader 拉起来的，给它 --preload 一个 hook 库，就能在 spawn 插件那一刻
# 把目标换成模块自带的 loader：插件文件一个字节不改（签名完好）、网关不用改、也不用抢时机。
# 自检（--list 走一遍依赖解析）不过就不带，绝不让一个 hook 把网关拖死。
# 排障：`touch /data/adb/ag2a/spawnhook.off` 即完全旁路。
ag2a_preload_arg() {
    _so="$MODDIR/lib/$AG2A_HOOK_LIB"
    [ -f "$_so" ] || return 0
    [ -f "$WORK/spawnhook.off" ] && return 0
    "$MODDIR/lib/$AG2A_LD_NAME" --library-path "$MODDIR/lib" --preload "$_so" \
        --list "$(ag2a_bin)" >/dev/null 2>&1 || return 0
    printf -- '--preload %s' "$_so"
}

# 启动器：loader --library-path <模块lib> [--preload <hook>] <二进制>
# 用 loader 直接跑，不 chroot、不建 rootfs：二进制只依赖 libc/libm/libgcc_s。
# ⚠ loader 与 lib/ 始终留在模块目录（上游从没换过它们，没必要跟着版本搬）。
ag2a_cmdline() {
    _pl=$(ag2a_preload_arg)
    printf '%s --library-path %s %s %s' \
        "$MODDIR/lib/$AG2A_LD_NAME" "$MODDIR/lib" "$_pl" "$(ag2a_bin)"
}

# ---------- 配置 ----------
# 自动更新开关：update.off 文件 或 AG2A_UPDATE_INTERVAL=0 都算关闭。
# 放 lib.sh 是因为 service.sh（要不要起定时器）、updater.sh（tick 该不该干活）、
# customize.sh（刷入时显示当前状态）三处都要判，各写一份必然会漂。
ag2a_update_on() {
    [ -f "$WORK/update.off" ] && return 1
    _u=$(sed -n 's/^AG2A_UPDATE_INTERVAL=\([0-9][0-9]*\).*/\1/p' "$WORK/update.conf" 2>/dev/null | head -n1)
    # 没有配置文件＝默认开启
    [ -n "$_u" ] || return 0
    [ "$_u" -gt 0 ] 2>/dev/null
}

# 端口优先级：$WORK/port（安装时写入，最高）> config.json 的 listen > 默认 3065
# 上游是「config.json 已有 listen 就原样沿用」，光改 env 里的 PORT 会被无视，所以端口单独落一个文件。
ag2a_get_port() {
    _pf="$(ag2a_data_dir)/port"
    _q=""
    [ -r "$_pf" ] && _q=$(tr -dc '0-9' < "$_pf" 2>/dev/null | head -n1)
    case "$_q" in
        '') : ;;
        *[!0-9]*) : ;;
        [1-9]*) [ "$_q" -ge 1024 ] 2>/dev/null && [ "$_q" -le 65535 ] 2>/dev/null && { echo "$_q"; return; } ;;
    esac
    _cfg="$(ag2a_data_dir)/config.json"
    _p=$(sed -n 's/.*"listen"[^"]*"\([^"]*\)".*/\1/p' "$_cfg" 2>/dev/null | head -n1)
    case "$_p" in
        *:*) _p=${_p##*:} ;;
    esac
    case "$_p" in
        '' | *[!0-9]*) _p=${AG2A_DEFAULT_PORT:-3065} ;;
    esac
    echo "$_p"
}

# 启动时按 $WORK/port 校正 config.json 的 listen：上游「已有 listen 就原样沿用」，
# 所以只有首启前写好 env、或改这里才真正换端口。
ag2a_force_port() {
    _fp=$1
    _cfg="$(ag2a_data_dir)/config.json"
    [ -n "$_fp" ] && [ -f "$_cfg" ] || return 0
    case "$_fp" in '' | *[!0-9]*) return 0 ;; esac
    if grep -q '"listen"' "$_cfg" 2>/dev/null; then
        sed -i "s|\"listen\"\([[:space:]]*:[[:space:]]*\)\"[^\"]*\"|\"listen\"\1\"0.0.0.0:$_fp\"|" "$_cfg" 2>/dev/null
    fi
}

# ---------- 网络 ----------
# 单个接口的 IPv4；先 ip -4，再退 ifconfig（两种 ifconfig 输出都认）
iface_ip() {
    _a=$(ip -4 -o addr show "$1" 2>/dev/null | awk 'NR==1{split($4,x,"/"); print x[1]}')
    [ -n "$_a" ] && { echo "$_a"; return; }
    ifconfig "$1" 2>/dev/null | sed -n \
        -e 's/.*[[:space:]]inet addr:\([0-9][0-9.]*\).*/\1/p' \
        -e 's/.*[[:space:]]inet[[:space:]][[:space:]]*\([0-9][0-9.]*\).*/\1/p' | head -n1
}

# 取一个 PC 能访问到的 IPv4：只认 wlan0 / ap*，故意不碰 rmnet/ccmni 蜂窝口
# （蜂窝地址 PC 连不上，显示它比不显示更误导）
wlan_ip() {
    _v=$(iface_ip wlan0)
    [ -n "$_v" ] && { echo "$_v"; return; }
    for _d in $(ip -4 -o addr show 2>/dev/null | awk '{print $2}' | grep -E '^(wlan|ap)') \
              $(ifconfig -a 2>/dev/null | sed -n 's/^\(\(wlan\|ap\)[a-zA-Z0-9_]*\)[[:space:]:].*/\1/p'); do
        [ "$_d" = wlan0 ] && continue
        _v=$(iface_ip "$_d")
        [ -n "$_v" ] && { echo "$_v"; return; }
    done
}

# ---------- 进程 ----------
# 判活 = 找 argv 里带 <运行体>/bin/agent2api-server 的进程。
#
# ⛔ 绝不要写成「遍历 /proc + 每个进程 fork 一次 tr/cat」：
#    本机约 1000 个进程时，那个写法单次实测 14.5 秒 CPU（2000 次 fork × 20–30ms）。
#    v1.5.x 把它放进每 3 秒一轮的 control.sh，永远追不上轮询间隔 ⇒ 单核 100% 跑满，
#    这是那一版整夜掉电的主因（CPU 2668mAh / 55%、UID 0 排第一）。
#    同一台机器对照：pgrep -f 单次 72ms、ps 单次 75ms，结果完全一致，快 200 倍以上。
#
# 匹配命令行里带 <模块目录> 的 agent2api-server（用完整路径，避免误杀别的同名进程）
#
# ⚠ 安装期路径错乱：customize.sh 是在临时目录（/data/adb/modules_update/ag2a 或
#   /dev/tmp/...）里执行的，从那里拉起的进程 cmdline 记的就是临时路径。安装完成把
#   目录搬到 /data/adb/modules/ag2a 之后，只按 $MODDIR 匹配就认不出这个进程，
#   于是 start 判定「没在跑」再起一个 ⇒ 端口被占、新进程起不来、旧进程变孤儿。
#   之前设备上那个指向 modules_update 的 5982 就是这么来的。所以两路都要匹配。
_ag2a_pids_one() {
    # $1 = cmdline 里要匹配的完整路径
    if command -v pgrep >/dev/null 2>&1; then
        for _p in $(pgrep -f "$1" 2>/dev/null); do
            # 排掉自己：调用方命令行里也可能带这个路径，不能把自己当网关（会误杀）
            case "$_p" in
                "$$" | "$PPID") continue ;;
            esac
            echo "$_p"
        done
        return 0
    fi
    # 没有 pgrep 的老 ROM：用 ps 一次读全表（1 次 fork）。
    # ⛔ 别退回「遍历 /proc + 每进程 fork 一次 tr」—— 那正是下面警告里 14.5 秒的写法。
    ps -A -o PID,ARGS 2>/dev/null | while read -r _pid _rest; do
        case "$_pid" in
            '' | *[!0-9]* | "$$" | "$PPID") continue ;;
        esac
        case " $_rest" in
            *"$1"*) echo "$_pid" ;;
        esac
    done
}

ag2a_pids() {
    # 四条路都要匹配：
    #   rt/                          运行体权威位置（v1.9.0 起）
    #   $MODDIR/bin/                 旧装法、或 rt 还没同步时的回退
    #   /data/adb/modules/ag2a/bin/  ⛔ 和 $MODDIR 不是一回事：customize.sh 里
    #                                $MODDIR=$MODPATH=…/modules_update/ag2a，
    #                                从那儿调 stop 必须能认出正跑着的旧网关
    #   modules_update/              安装期从临时目录拉起的进程（见上面那段警告）
    # 四者输出可能有重复，统一用 awk 去重。
    for _q in "$(ag2a_data_dir)/rt/bin/$AG2A_BIN_NAME" \
              "$MODDIR/bin/$AG2A_BIN_NAME" \
              "/data/adb/modules/$AG2A_ID/bin/$AG2A_BIN_NAME" \
              "/data/adb/modules_update/$AG2A_ID/bin/$AG2A_BIN_NAME"; do
        [ -n "$_q" ] || continue
        _ag2a_pids_one "$_q"
    done | awk 'NF && !_s[$0]++'
}

ag2a_running() {
    [ -n "$(ag2a_pids)" ]
}

# 端口是否真的在 LISTEN。
# 「进程还在」≠「服务可用」：网关可能起来了但端口没绑上（配置错、端口被占）。
# 只读 /proc/net/tcp{,6}，一次 awk 判完，不连网络、不依赖 curl。
#   /proc/net/tcp 的 $4 是状态，0A = LISTEN；$2 是 local_address，形如 00000000:0BF9
ag2a_port_listen() {
    _pt=$1
    case "$_pt" in '' | *[!0-9]*) return 1 ;; esac
    _hx=$(printf '%04X' "$_pt" 2>/dev/null)
    [ -n "$_hx" ] || return 1
    awk -v h="$_hx" '
        FNR == 1 { next }
        $4 == "0A" { n = split($2, a, ":"); if (a[n] == h) { f = 1; exit } }
        END { exit(f ? 0 : 1) }
    ' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

# 看门狗的 pid；没在跑则返回非 0。
# 同样必须校验 cmdline：pid 复用会把无关进程当成看门狗（然后被 kill 掉）。
ag2a_watchdog_pid() {
    _wp=$(cat "$(ag2a_data_dir)/watchdog.pid" 2>/dev/null)
    case "$_wp" in '' | *[!0-9]*) return 1 ;; esac
    kill -0 "$_wp" 2>/dev/null || return 1
    grep -q 'watchdog\.sh' "/proc/$_wp/cmdline" 2>/dev/null || return 1
    echo "$_wp"
}

# ---------- 证书 ----------
# rustls 不内嵌根证书（实测 BEGIN CERTIFICATE 计数 0），必须给 SSL_CERT_FILE。
# 候选顺序：模块自带 → Android 13- 的 cacerts → Android 14+ 的 conscrypt APEX
# ⚠ 必须带 export：调用方是 `eval "$(ag2a_cert_env)"`，不加 export 只是给当前 shell
#   设了个变量，随后 exec 出去的网关（和它 spawn 的插件）一个都看不到 ⇒ rustls 没根证书。
ag2a_cert_env() {
    if [ -f "$MODDIR/etc/ca-certificates.crt" ]; then
        echo "export SSL_CERT_FILE=$MODDIR/etc/ca-certificates.crt"
        return
    fi
    for _d in /system/etc/security/cacerts \
              /apex/com.android.conscrypt/cacerts; do
        if [ -d "$_d" ]; then
            echo "export SSL_CERT_DIR=$_d"
            return
        fi
    done
}

# ---------- 时区 ----------
# 二进制读 /usr/share/zoneinfo（实测命中 TZif 与路径字符串）。
# TZ 直接给文件绝对路径时 glibc 不再拼 zoneinfo 目录，所以可以指模块内的单个 tzfile。
# ⚠ 同样必须 export（否则网关仍按 UTC 算签到/额度窗口）。
ag2a_tz_env() {
    if [ -f "$MODDIR/zoneinfo/Asia/Shanghai" ]; then
        echo "export TZ=$MODDIR/zoneinfo/Asia/Shanghai"
    fi
}

# ---------- 日志 ----------
# 超限只留尾部；调用前必须保证没有写入者（只在启动时调用）
ag2a_rotate() {
    _f=$1
    _max=$2
    [ -f "$_f" ] || return 0
    [ "$(wc -c < "$_f" 2>/dev/null | tr -d ' ')" -gt "$_max" ] 2>/dev/null || return 0
    tail -c $((_max / 4)) "$_f" > "$_f.tmp" 2>/dev/null && mv -f "$_f.tmp" "$_f"
}

# ---------- 管理员播种 ----------
# 用 POST /api/panel/setup 建管理员（CAPTCHA_ENABLED=0 时免人机验证）。
# 返回 0=建好 1=还没建好（未监听/被拒）3=库里已有管理员。
# 面板只对本机开放，所以打 127.0.0.1；不依赖 curl（Android 12 起系统没带）。
ag2a_seed_admin() {
    _port=$1
    [ -n "$_port" ] || return 1
    [ -f "$WORK/admin.json" ] && return 3
    _body="{\"username\":\"$AG2A_ADMIN_USER\",\"password\":\"$AG2A_ADMIN_PASSWORD\"}"
    _out=""
    if command -v curl >/dev/null 2>&1; then
        _out=$(curl -s --noproxy '*' --max-time 8 -X POST -H 'Content-Type: application/json' \
               -d "$_body" "http://127.0.0.1:$_port/api/panel/setup" 2>/dev/null)
    elif [ -n "$AG2A_BUSYBOX" ]; then
        # 用 busybox nc 发 POST（busybox wget 只有 GET，dash 没 /dev/tcp）
        _out=$(printf 'POST /api/panel/setup HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s' \
                   "${#_body}" "$_body" \
               | "$AG2A_BUSYBOX" nc 127.0.0.1 "$_port" 2>/dev/null | sed '1,/^$/d')
    else
        return 1
    fi
    case "$_out" in
        *'"success":true'*)
            printf '%s\n' "$_out" > "$WORK/admin.json"
            chmod 0600 "$WORK/admin.json" 2>/dev/null
            : > "$WORK/admin.created"
            return 0 ;;
        '') return 1 ;;
        *)  printf '%s\n' "$_out" >> "$WORK/seed.log" 2>/dev/null
            return 1 ;;
    esac
}

# ---------- DNS（两种上游形态，一套壳层兜底） ----------
# 上游在 3.5.1 换了解析器，这里必须同时伺候两代，否则总有一代会「连不上网」：
#
# 【3.5.0 及以前】网关运行时自己解出 dnsfix/dnsproxy，靠 127.0.0.1:53 解析。
#   踩过两档子事：
#     1) 解出来的 dnsproxy 被权限归一化收成 0600，execve 永远 EACCES 且网关不重试；
#     2) dnsproxy 被优雅停掉一次后，运行期不再拉 —— 全进程组 DNS 瘫痪，不重启不自愈。
#   兜底：ag2a_dns_fix_perms 每次启动纠执行位；dnsd.sh 事件驱动保活（wait 不轮询）。
#
# 【3.5.1 起】二进制里已无 dnsfix/dnsproxy/127.0.0.1:53 任何痕迹，改为进程内 hickory
#   解析器，只读系统 /etc/resolv.conf（二进制里也没有任何硬编码公共 DNS、没有可配的
#   DNS 环境变量）。而 Android 根本没有 /etc/resolv.conf —— 解析必然失败：
#     dns error → failed to lookup address information: Temporary failure in name resolution
#   这就是 26.11.24_1（3.5.1）在手机上「连不上网」的根因，Linux 上同样的二进制一切正常。
#   兜底：ag2a_write_resolv 在启动网关前写一份 resolv.conf（默认阿里 + DNSPod 并行），
#   路径给网关自身和它 spawn 的插件一起用。
#   注意：Android / 是只读的，写不进去；由 ag2a_resolv_env 判断能不能用，
#   实在没有可写位置时才退回「让 dnsproxy 监听 127.0.0.1:53」那套。

# 网关用的上游 DNS 列表（每行一个 IPv4）。可配：$WORK/dnsfix/upstreams 里写
# "nameserver x.x.x.x" 或纯 IP，一行一个；非法行忽略，最多 4 条；缺省阿里 + DNSPod。
ag2a_dns_servers() {
    _uf="$(ag2a_data_dir)/dnsfix/upstreams"
    _ul=""
    if [ -r "$_uf" ]; then
        _ul=$(sed -e 's/\r$//' -e 's/^[[:space:]]*nameserver[[:space:]]*//' "$_uf" 2>/dev/null \
              | grep -v '^[[:space:]]*#' \
              | tr -d ' \t' \
              | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
              | head -n 4)
    fi
    [ -n "$_ul" ] || _ul="223.5.5.5
119.29.29.29"
    printf '%s\n' "$_ul"
}

# 生成一份 resolv.conf，把路径 echo 出来；返回非 0 表示没有可写位置。
# 候选顺序（先挑能写的，内容每次启动重写，幂等）：
#   $WORK/etc/resolv.conf      数据目录，最稳，网关 HOME 就在这儿
#   /data/local/tmp/resolv.conf
# 注意：hickory/system-config 只认编译期写死的 /etc/resolv.conf。Android 的 / 通常是
# read-only，若无法 bind-mount 到 /etc/resolv.conf，则写入的数据目录版本只能供
# 「以 LD_PRELOAD 或 chroot 方式启动」的场景使用 —— 因此下面还提供 dnsproxy 复用路径。
ag2a_write_resolv() {
    _rd="$(ag2a_data_dir)/etc"
    mkdir -p "$_rd" 2>/dev/null || return 1
    _rf="$_rd/resolv.conf"
    {
        echo "# ag2a: 由 lib.sh 生成，每次启动重写。上游解析器只认这里。"
        ag2a_dns_servers | sed 's/^/nameserver /'
        echo "options timeout:2 attempts:2"
    } > "$_rf.new" 2>/dev/null || return 1
    mv -f "$_rf.new" "$_rf" 2>/dev/null || return 1
    echo "$_rf"
}

# 生成 resolv.conf 副本（仅供排查/文档参考，不参与解析）。
# ⚠ 关键结论（实测）：Android 根分区 erofs 只读，既没有 /etc/resolv.conf，
#   bind mount 也建不出目标文件（挂载直接 ENOENT）。
#   但 glibc 在「没有可用 resolv.conf」时会回落到 127.0.0.1:53 发查询（已抓包证实），
#   所以正确解法不是伪造文件，而是确保有人在 127.0.0.1:53 应答 —— 即 dnsproxy。
#   LD_PRELOAD 重定向方案已实测无效：glibc 读 resolv.conf 走内部符号，不经过 PLT，
#   open/fopen/stat 全都拦不到。不要再往那个方向做。
ag2a_resolv_env() {
    ag2a_write_resolv >/dev/null 2>&1
    return 0
}

# 执行位自愈（3.5.0 及以前那代的 dnsproxy）。目录可能不存在，静默失败。
ag2a_dns_fix_perms() {
    chmod 755 "$(ag2a_data_dir)/dnsfix/dnsproxy" 2>/dev/null
    return 0
}

# 53 端口（或 IPv6）有没有人在听。53 = 0x0035。
# ⚠ TCP 和 UDP 都要看：dnsstub 是 UDP-only，而已绑定的 UDP socket 状态是 07（不是 TCP 的
#   0A = LISTEN）。只看 /proc/net/tcp 会永远判「没在听」—— 结果 dnsd 的「53 已被占用就让位」
#   对最常见的场景（别的 DNS 组件只开 UDP）完全失效，会无限重拉，check.sh 也一直误报
#   「网关外连将全部 DNS 失败」。
#   按 FILENAME 区分 udp/tcp（不能数 FNR==1 的序号：没有 IPv6 时 /proc/net/tcp6 打不开，
#   序号会错位，udp 被当成 tcp 判）。
# 与 ag2a_port_listen 同路数：只读 /proc/net/*，一次 awk 判完，不 fork 不联网。
ag2a_dns_listen() {
    # ⚠ 先把存在的表挑出来再交给 awk：gawk/busybox awk 对**命令行上打不开的文件**
    #   是致命错误（会直接中止，连后面的表都不看），而少数内核裁掉了 tcp6/udp6。
    _fl=""
    for _f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
        [ -r "$_f" ] && _fl="$_fl $_f"
    done
    [ -n "$_fl" ] || return 1
    # shellcheck disable=SC2086
    awk '
        FNR == 1 { isudp = (index(FILENAME, "/udp") > 0); next }
        {
            n = split($2, a, ":")
            if (n > 0 && a[n] == "0035") {
                if (isudp) { if ($4 == "07") { f = 1; exit } }
                else if ($4 == "0A") { f = 1; exit }
            }
        }
        END { exit(f ? 0 : 1) }
    ' $_fl 2>/dev/null
}

# dnsproxy 的 -u 参数串（3.5.0 及以前那代用）。故意不做引号包裹，逐词传参。
ag2a_dns_upstreams() {
    _uf="$(ag2a_data_dir)/dnsfix/upstreams"
    _ul=""
    if [ -r "$_uf" ]; then
        _ul=$(sed -e 's/\r$//' "$_uf" 2>/dev/null \
              | grep -v '^[[:space:]]*#' \
              | tr -d ' \t' \
              | grep -E '^[A-Za-z0-9+._/:@%?&=-]+$' \
              | head -n 6)
    fi
    [ -n "$_ul" ] || _ul="udp://223.5.5.5:53
udp://119.29.29.29:53"
    for _u in $_ul; do printf -- '-u %s ' "$_u"; done
}

# dnsd 的 pid；没在跑返回非 0。pidfile + cmdline 双重校验，防 pid 复用误杀。
ag2a_dnsd_pid() {
    _dp=$(cat "$(ag2a_data_dir)/dnsd.pid" 2>/dev/null)
    case "$_dp" in '' | *[!0-9]*) return 1 ;; esac
    kill -0 "$_dp" 2>/dev/null || return 1
    grep -q 'dnsd\.sh' "/proc/$_dp/cmdline" 2>/dev/null || return 1
    echo "$_dp"
}

# 网关是否需要 dnsproxy 兜底（= 3.5.0 及以前那一代）。
# 判据：二进制里是否还带 dnsfix/dnsproxy 痕迹。新代没有，就不该再起 dnsproxy，
# 免得白占 10MB 内存和 53 端口。
ag2a_needs_dnsproxy() {
    _b=$(ag2a_bin)
    [ -f "$_b" ] || return 1
    # 只读前 8MB 做采样：两次 O(8MB) 读足够命中（实测新旧两代差异极明显）。
    _hit=$(head -c 8388608 "$_b" 2>/dev/null | grep -ac 'dnsfix' 2>/dev/null)
    [ "${_hit:-0}" -gt 0 ] 2>/dev/null
}
