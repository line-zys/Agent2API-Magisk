#!/system/bin/sh
# 兼容壳。v1.5.x 的 control.sh 是「每 3 秒扫 /proc 判活 + 每 30 秒刷 description」的
# 常驻循环 —— 那是耗电元凶（CPU 永远进不了深度休眠）。
# v1.6.0 起：启停全部由 service.sh 一次性完成，description 由 refresh.sh 按需刷。
# 本文件只做转发，保证旧的调用（action.sh / uninstall.sh / 手打）不报错。
#
# ⚠ 只转发认识的子命令。以前是 `exec sh service.sh "${1:-start}"` 原样转发，于是
#   `sh control.sh status`（旧版调用）会一路掉到 service.sh 末尾的**前台 exec**：
#   调用方（管理器 UI / adb / Shizuku）永久阻塞，进程还被 exec 成网关本体。

MODDIR="$(dirname "$(readlink -f "$0")")"
case "$MODDIR" in
    /data/adb/modules/ag2a | /data/adb/modules_update/ag2a) : ;;
    *)
        case "$0" in
            /*) MODDIR=$(dirname "$0") ;;
            *)  MODDIR=/data/adb/modules/ag2a ;;
        esac
        ;;
esac

case "$1" in
    '' | start | stop | restart | crontab)
        exec /system/bin/sh "$MODDIR/service.sh" "${1:-start}" ;;
    *)
        echo "control.sh 已改为一次性语义（v1.6.0 起）。用法：" >&2
        echo "  sh control.sh [start|stop|restart|crontab]" >&2
        echo "其它子命令请直接用：sh $MODDIR/action.sh 或 sh $MODDIR/service.sh" >&2
        exit 2 ;;
esac
