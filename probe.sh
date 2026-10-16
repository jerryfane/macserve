#!/bin/bash
# Scratch native probe 4 for v0.1.10 (do not merge): capture fixtures.
U=$(id -u)
go build -o /tmp/envprobe ./scratch/envprobe || exit 1
P=/tmp/envprobe
mkdir -p /tmp/cap
launchctl kickstart user/$U/com.apple.TrustEvaluationAgent; sleep 2
cap() { # name target
  sudo launchctl print "$2" > /tmp/cap/$1.txt
  pid=$(awk '/^\tpid = /{print $3}' /tmp/cap/$1.txt)
  sudo $P raw $pid > /tmp/cap/$1.bin
  echo "captured $1 $2 pid=$pid"
}
cap gui-dock gui/$U/com.apple.Dock
cap gui-finder gui/$U/com.apple.Finder
cap gui-corespeechd gui/$U/com.apple.corespeechd
cap user-trustevaluationagent user/$U/com.apple.TrustEvaluationAgent
cap user-containermanagerd user/$U/com.apple.containermanagerd
launchctl setenv PROBE_ENV poisoned
launchctl kickstart -k gui/$U/com.apple.corespeechd; sleep 3
cap gui-corespeechd-setenv gui/$U/com.apple.corespeechd
launchctl unsetenv PROBE_ENV
launchctl kickstart -k gui/$U/com.apple.corespeechd; sleep 2
echo "##### ps"
ps -axo pid=,ppid=,uid=,comm= | grep -E 'trustevaluationagent|containermanagerd|Dock|Finder|corespeechd'
cd /tmp/cap && tar czf - . | base64 > /tmp/cap.b64
echo "##### BEGIN CAPTURE"
cat /tmp/cap.b64
echo "##### END CAPTURE"
exit 0
