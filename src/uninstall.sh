#!/system/bin/sh
# 卸载：停进程 + 删模块目录 + 删数据目录。
# ⛔ 只碰写死的两个路径，且必须精确匹配白名单；其它一律不删。
#    绝不用通配符、绝不 rm -rf 任何动态拼出来的路径。
#    想重装后保留账号：卸载前 touch /data/adb/ag2a/keep

MODDIR=/data/adb/modules/ag2a
WORK=/data/adb/ag2a

# 白名单删除：只认这三个精确路径，其它一律拒绝（防变量异常时误删）
safe_rm() {
    case "$1" in
        /data/adb/modules/ag2a | /data/adb/modules_update/ag2a | /data/adb/ag2a)
            [ -d "$1" ] || return 0
            rm -rf "$1" 2>/dev/null
            [ -d "$1" ] && return 1
            return 0 ;;
        *)
            echo "[ag2a] 拒绝删除非白名单路径: $1" >&2
            return 1 ;;
    esac
}

# 先停网关再停更新定时器（v1.6.2 起定时器是个 sleep 进程，不是 crond）
_svc="$MODDIR/service.sh"
if [ -f "$_svc" ]; then
    sh "$_svc" stop >/dev/null 2>&1
fi
# 更新定时器：按 pidfile 精确杀掉（不 pkill，避免误伤同名进程）
if [ -f "$WORK/update.timer.pid" ]; then
    _t=$(cat "$WORK/update.timer.pid" 2>/dev/null)
    if [ -n "$_t" ]; then
        kill "$_t" 2>/dev/null
        sleep 0.2 2>/dev/null || sleep 1
        kill -9 "$_t" 2>/dev/null
    fi
    rm -f "$WORK/update.timer.pid" 2>/dev/null
fi
# 老版本（v1.6.0/1）遗留的 crontab 与 crond 一并清掉
rm -f "$WORK/crontab" "$WORK/crontab.tmp" 2>/dev/null
# 插件解释器软链：指向本模块目录，卸载后就是死链，带走
rm -f /data/adb/ag2a/ld.so 2>/dev/null

# 兜底：老版本的常驻循环 / 网关进程（v1.5.x 及以前）+ 看门狗 + dnsstub。
# 四条路径都要扫：v1.9.0 起网关从 rt/ 起，模块目录里那份只是回退（见 lib.sh）。
#
# ⚠ 不能只写 `pkill -f ...`：
#   a) 本机可能根本没有 pkill（toybox 没编 / PATH 里没 busybox），命令找不到时
#      `2>/dev/null` 会把错误吞掉，一个进程都不杀 —— 结果删了目录还留着看门狗和
#      dnsstub：端口被永久占住（重装同端口必失败）、孤儿看门狗每 60 秒去拉已删除的
#      service.sh、53 被已删除的 stub 顶着，新装的 dnsd 只能「让位退出」。
#   b) 清单里漏了 watchdog.sh 和 bin/dnsstub —— 正是上面那两条幽灵。
BB=""
for _bb in /data/adb/ap/bin/busybox /data/adb/magisk/busybox /data/adb/ksu/bin/busybox; do
    [ -x "$_bb" ] && { BB="$_bb"; break; }
done

# $1 = cmdline 片段；$2 = 空（TERM）或 -9（KILL）
kill_pat() {
    if command -v pkill >/dev/null 2>&1 && pkill $2 -f "$1" 2>/dev/null; then
        return 0
    fi
    if [ -n "$BB" ] && "$BB" pkill $2 -f "$1" 2>/dev/null; then
        return 0
    fi
    # 兜底：ps 一次读全表（⛔ 不要遍历 /proc 逐进程 fork，那在千进程机器上是十几秒 CPU）
    ps -A -o PID,ARGS 2>/dev/null | while read -r _kp _kr; do
        case "$_kp" in '' | *[!0-9]*) continue ;; esac
        case " $_kr" in
            *"$1"*) kill $2 "$_kp" 2>/dev/null ;;
        esac
    done
    return 0
}

# 要扫的进程：网关（三条路径，见 lib.sh）+ 看门狗 + 旧版循环 + 本地 DNS
for _pat in "$MODDIR/bin/agent2api-server" "$WORK/rt/bin/agent2api-server" \
            "/data/adb/modules_update/ag2a/bin/agent2api-server" \
            "$MODDIR/watchdog.sh" "$MODDIR/control.sh" "$MODDIR/updater.sh" \
            "$MODDIR/dnsd.sh" "$MODDIR/bin/dnsstub" "$WORK/dnsfix/dnsproxy"; do
    kill_pat "$_pat" ""
done
sleep 1
for _pat in "$MODDIR/bin/agent2api-server" "$WORK/rt/bin/agent2api-server" \
            "/data/adb/modules_update/ag2a/bin/agent2api-server" \
            "$MODDIR/watchdog.sh" "$MODDIR/control.sh" "$MODDIR/updater.sh" \
            "$MODDIR/dnsd.sh" "$MODDIR/bin/dnsstub" "$WORK/dnsfix/dnsproxy"; do
    kill_pat "$_pat" -9
done

echo "[ag2a] 网关 / 看门狗 / dnsstub / 更新排班 / 旧版循环已停止。"
# 运行体自检：rt/ 里还留着二进制就说明进程没停干净（下面删数据目录会连带删掉）
if [ -f "$WORK/rt/bin/agent2api-server" ]; then
    _still=""
    if command -v pgrep >/dev/null 2>&1; then
        _still=$(pgrep -f "$WORK/rt/bin/agent2api-server" 2>/dev/null)
    elif [ -n "$BB" ]; then
        _still=$("$BB" pgrep -f "$WORK/rt/bin/agent2api-server" 2>/dev/null)
    fi
    [ -n "$_still" ] && echo "[ag2a] ⚠ 仍有进程（$_still）在用 $WORK/rt 里的二进制，重启后再手动删一次 $WORK"
fi

# remove/disable 标记：目录删成功了就不必留（留着会让管理器把它标成「已停用」而不是消失）
cd / 2>/dev/null
if safe_rm "$MODDIR"; then
    safe_rm /data/adb/modules_update/ag2a
else
    # 删不掉才落标记，交给管理器下次启动处理
    touch "$MODDIR/remove" 2>/dev/null
    [ -f "$MODDIR/disable" ] || touch "$MODDIR/disable" 2>/dev/null
    echo "[ag2a] ⚠ 模块目录删不掉，已写 remove/disable 标记，重启后由管理器清理" >&2
fi

# 历史残留：v1.3.3~1.3.4 的刷入脚本曾在 /data/local/tmp/.ag2a_key.<pid> 里传按键结果
# （正常流程当场删掉，安装被杀才会留下）。v1.3.5 起不再写任何临时文件。
# 只删「前缀 + 纯数字」的文件，其它一概不碰；也不用 .ag2a_* 这种宽通配。
for _k in /data/local/tmp/.ag2a_key.*; do
    [ -f "$_k" ] || continue
    case "${_k##*/.ag2a_key.}" in
        '' | *[!0-9]*) continue ;;
    esac
    rm -f "$_k" 2>/dev/null
done

# 数据目录：账号库、配置、日志 —— 一并清掉
if [ -f "$WORK/keep" ]; then
    echo "[ag2a] 检测到 $WORK/keep，保留数据目录（重装可继续用同一个账号）。"
else
    if safe_rm "$WORK"; then
        echo "[ag2a] 数据目录已删除（$WORK）。"
    else
        echo "[ag2a] 数据目录没删干净（$WORK），重启后再手动删一次。"
    fi
fi

if [ -d "$MODDIR" ]; then
    echo "[ag2a] 模块目录没删掉（$MODDIR），已打 remove 标记：重启后由管理器清除。"
else
    echo "[ag2a] 模块已卸载（目录已删除，管理器列表刷新后即消失）。"
fi
