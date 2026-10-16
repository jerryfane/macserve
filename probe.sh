#!/bin/bash
U=$(id -u)
go test -c -o /tmp/w.test ./internal/worker || exit 1
pidof() { launchctl print $1 2>/dev/null | awk '/^\tpid = /{print $3}'; }
C=gui/$U/com.apple.corespeechd
A=$(pidof $C); F=$(pgrep -x Finder | head -1)
Q=$(ps -axo pid=,uid=,comm= | awk -v u=$U '$2==u && $3 ~ /QuickLookUIService$/ {print $1; exit}')
echo "A=$A F=$F Q=$Q"
sudo PROBE_STAGE=describe PROBE_PIDS=$A,$F,$Q /tmp/w.test -test.run TestProbeLive -test.v 2>&1 | grep -v "^=== RUN"
check() { sudo PROBE_STAGE=check PROBE_NAME="$1" PROBE_PID=$2 /tmp/w.test -test.run TestProbeLive 2>&1 | grep "CHECK\|RESIDUAL\|FAIL"; }
waitnew() { for i in $(seq 1 40); do P=$(pidof $C); [ -n "$P" ] && [ "$P" != "$1" ] && echo $P && return; sleep 1; done; }
check "audited still running (not candidate)" $A
sudo kill -9 $A; B=$(waitnew $A); echo "relaunched B=$B"
check "launchd relaunch after crash" $B
launchctl setenv PROBE_ENV poisoned; launchctl kickstart -k $C; E=$(waitnew $B); echo "E=$E"
check "relaunch with launchctl setenv" $E
launchctl unsetenv PROBE_ENV; launchctl kickstart -k $C; G=$(waitnew $E); echo "G=$G"
check "job kickstart -k, clean env" $G
launchctl bootout $C; launchctl submit -l com.apple.corespeechd -- /System/Library/PrivateFrameworks/CoreSpeech.framework/corespeechd; X=$(waitnew $G); echo "X=$X"
check "job launchctl submit, same label+binary" $X
launchctl remove com.apple.corespeechd; sleep 1
mkdir -p ~/Library/LaunchAgents; plutil -convert xml1 -o ~/Library/LaunchAgents/com.apple.corespeechd.plist /System/Library/LaunchAgents/com.apple.corespeechd.plist
plutil -replace RunAtLoad -bool true ~/Library/LaunchAgents/com.apple.corespeechd.plist
launchctl bootstrap gui/$U ~/Library/LaunchAgents/com.apple.corespeechd.plist; Y=$(waitnew $X); echo "Y=$Y"
check "job ~/Library/LaunchAgents copy, same label+binary" $Y
launchctl bootout $C; rm ~/Library/LaunchAgents/com.apple.corespeechd.plist; sleep 1
launchctl bootstrap gui/$U /System/Library/LaunchAgents/com.apple.corespeechd.plist; Z=$(waitnew $Y); echo "Z=$Z"
check "job re-bootstrap of the system plist" $Z
cp /System/Library/PrivateFrameworks/CoreSpeech.framework/corespeechd /tmp/corespeechd-copy 2>/dev/null; echo "== done"
exit 0
