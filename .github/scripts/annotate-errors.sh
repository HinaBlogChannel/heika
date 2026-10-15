#!/usr/bin/env bash
# ビルドのログから、エラーらしい行と最後の部分を annotation に出す。
# annotation は公開の API でトークンなしに読めるので、ログを貼ってもらわなくても失敗の理由がわかる。
#
# 使い方: annotate-errors.sh ログのファイル
set -u

log=$1
[ -f "$log" ] || exit 0

# 1つの annotation に複数の行を入れるため、改行などを workflow command の書き方に直す
emit() {
    local title=$1 text
    text=$(sed "s/$(printf '\033')\[[0-9;]*[A-Za-z]//g")
    [ -n "$text" ] || return 0
    text=${text//'%'/'%25'}
    text=${text//$'\r'/'%0D'}
    text=${text//$'\n'/'%0A'}
    echo "::error title=$title::$text"
}

grep -nE 'error|Error|ERROR|FAILED|failed|panicked' "$log" | tail -n 60 | emit "エラーらしい行（$log）"
tail -n 40 "$log" | emit "最後の40行（$log）"
