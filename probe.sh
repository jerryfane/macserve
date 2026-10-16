#!/bin/bash
# Scratch native probe for v0.1.10 (do not merge).
U=$(id -u)
sw_vers
echo "manager: $(launchctl managername) uid=$(launchctl manageruid) pid=$(launchctl managerpid)"
go build -o /tmp/envprobe ./scratch/envprobe || exit 1
P=/tmp/envprobe
hdr() { launchctl print "$1" | awk '/^\tservices = \{/{exit} {print}'; }
echo "##### domain headers"; hdr gui/$U; hdr user/$U
echo "##### GUI anchors"
ps -axo pid=,ppid=,uid=,comm= | awk -v u=$U '$3==u' | grep -E 'loginwindow|/Dock$|/Finder$|Terminal|zsh|trustevaluationagent|corespeechd' 
for n in loginwindow Dock Finder; do p=$(pgrep -x -u $U $n | head -1); echo "== $n pid=$p"; [ -n "$p" ] && sudo launchctl procinfo $p 2>/dev/null | grep -E '^\s*(program path|domain|responsible pid|path|type|label|service) ' | head -12; done
echo "##### TrustEvaluationAgent plist"
plutil -p /System/Library/LaunchAgents/com.apple.TrustEvaluationAgent.plist
for d in gui user; do echo "== print $d/$U/com.apple.TrustEvaluationAgent"; launchctl print $d/$U/com.apple.TrustEvaluationAgent 2>&1 | head -60; done
echo "##### full dump"
sudo $P dump gui/$U user/$U > /tmp/dump.json
$P summarize < /tmp/dump.json
echo "##### TEA on-demand behaviour"
T=$(pgrep -x -u $U trustevaluationagent | head -1); echo "TEA running pid=$T"
if [ -z "$T" ]; then
  for d in gui user; do launchctl kickstart $d/$U/com.apple.TrustEvaluationAgent 2>&1 && echo "kickstarted in $d"; done
  sleep 2; T=$(pgrep -x -u $U trustevaluationagent | head -1); echo "TEA after kickstart pid=$T"
fi
sudo $P one gui/$U/com.apple.TrustEvaluationAgent user/$U/com.apple.TrustEvaluationAgent
if [ -n "$T" ]; then
  kill -TERM $T; date +%T.%N
  for i in $(seq 1 30); do N=$(pgrep -x -u $U trustevaluationagent | head -1); [ -n "$N" ] && [ "$N" != "$T" ] && { echo "TEA respawned pid=$N after ${i}s"; break; }; sleep 1; done
  [ -z "$N" ] && echo "TEA not respawned within 30s"
  # Ask for the service on demand through the Security framework.
  security verify-cert -c /System/Library/Keychains/SystemRootCertificates.keychain >/dev/null 2>&1
  security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | awk '/BEGIN/{n++} n==1' > /tmp/root.pem; security verify-cert -c /tmp/root.pem 2>&1 | head -2
  sleep 2; N=$(pgrep -x -u $U trustevaluationagent | head -1); echo "TEA after verify-cert pid=$N"
  [ -n "$N" ] && ps -o pid=,ppid=,uid=,lstart=,comm= -p $N
  sudo $P one gui/$U/com.apple.TrustEvaluationAgent user/$U/com.apple.TrustEvaluationAgent | grep -E 'DOMAINPART|"Path"|"Type"|"PID"|"PPID"|"Err"'
fi
echo "##### setenv placement"
launchctl setenv PROBE_ENV poisoned
launchctl setenv OSLogRateLimit 7
launchctl setenv TMPDIR /tmp/poisoned-tmp/
echo "getenv: PROBE_ENV=$(launchctl getenv PROBE_ENV) OSLogRateLimit=$(launchctl getenv OSLogRateLimit)"
hdr gui/$U | grep -A8 environment; hdr user/$U | grep -A8 environment
for t in gui/$U/com.apple.corespeechd gui/$U/com.apple.TrustEvaluationAgent user/$U/com.apple.TrustEvaluationAgent; do
  launchctl kickstart -k $t >/dev/null 2>&1 && echo "kickstart -k $t ok"
done
sleep 3
sudo $P one gui/$U/com.apple.corespeechd gui/$U/com.apple.TrustEvaluationAgent user/$U/com.apple.TrustEvaluationAgent
echo "##### clean env again"
launchctl unsetenv PROBE_ENV; launchctl unsetenv OSLogRateLimit; launchctl unsetenv TMPDIR
for t in gui/$U/com.apple.corespeechd gui/$U/com.apple.TrustEvaluationAgent user/$U/com.apple.TrustEvaluationAgent; do
  launchctl kickstart -k $t >/dev/null 2>&1 && echo "kickstart -k $t ok"
done
sleep 3
sudo $P one gui/$U/com.apple.corespeechd gui/$U/com.apple.TrustEvaluationAgent user/$U/com.apple.TrustEvaluationAgent | grep DOMAINPART
echo "##### done"
exit 0
