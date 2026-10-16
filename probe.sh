#!/bin/bash
# Scratch native probe 2 for v0.1.10 (do not merge).
U=$(id -u)
go build -o /tmp/envprobe ./scratch/envprobe || exit 1
P=/tmp/envprobe
order() { jq -r '.[] | select(.Path | startswith("/System/Library/LaunchAgents/")) | select(.Type=="LaunchAgent") | select(.Err=="") | . as $s | ($s.Target | split("/")[0]) + " " + ([$s.Env[] | select((split("=")[0]) as $k | ($s.EnvDict | has($k) | not) and $k != "XPC_FLAGS")] | join(" "))' | sort | uniq -c | cut -c1-400; }
xflags() { jq -r '.[] | select(.Err=="") | .Target + " " + ([.Env[] | select(startswith("XPC_FLAGS="))] | join(","))' | awk '{print $2}' | sort | uniq -c; }
echo "##### ordered domain parts (count, domain, ordered env)"
sudo $P dump gui/$U user/$U > /tmp/d0.json
order < /tmp/d0.json
echo "##### XPC_FLAGS values"
xflags < /tmp/d0.json
echo "##### service-type census"
jq -r '.[] | (.Target|split("/")[0]) + " " + .Type + " " + (if (.Path|startswith("/System/Library/LaunchAgents/")) then "sysplist" elif (.Path|endswith(".xpc")) then "xpc" else .Path end)' /tmp/d0.json | sort | uniq -c
echo "##### setenv XPC_FLAGS and a service-dict key"
launchctl setenv XPC_FLAGS 0x7fffffff
launchctl setenv XPC_SERVICE_NAME com.example.poison
launchctl setenv MallocSpaceEfficient 0
launchctl kickstart -k gui/$U/com.apple.corespeechd && sleep 3
sudo $P one gui/$U/com.apple.corespeechd | jq -Rr 'select(startswith("DOMAINPART") or startswith(" \"XPC") or contains("XPC_FLAGS") or contains("XPC_SERVICE_NAME") or contains("MallocSpace"))' 2>/dev/null || sudo $P one gui/$U/com.apple.corespeechd | grep -E 'XPC|Malloc|DOMAINPART'
launchctl unsetenv XPC_FLAGS; launchctl unsetenv XPC_SERVICE_NAME; launchctl unsetenv MallocSpaceEfficient
launchctl kickstart -k gui/$U/com.apple.corespeechd && sleep 3
sudo $P one gui/$U/com.apple.corespeechd | grep -E 'XPC|Malloc|DOMAINPART'
echo "##### user-domain setenv reach"
# A job process in the gui domain cannot address the user domain's environment
# with setenv; try asuser-style and bootstrap-based routes and observe.
launchctl setenv PROBE_GUI only-gui
launchctl kickstart -k user/$U/com.apple.TrustEvaluationAgent && sleep 2
sudo $P one user/$U/com.apple.TrustEvaluationAgent | grep DOMAINPART
launchctl unsetenv PROBE_GUI
echo "##### TEA on-demand triggers"
T=$(pgrep -x -u $U trustevaluationagent | head -1); echo "TEA pid=$T"
[ -n "$T" ] && kill -9 $T
sleep 1
for c in "security dump-trust-settings" "security dump-trust-settings -d" "security trust-settings-export /tmp/ts.plist" "security find-identity -v" "/usr/bin/curl -sS -o /dev/null https://github.com"; do
  $c >/dev/null 2>&1; sleep 1; N=$(pgrep -x -u $U trustevaluationagent | head -1); echo "after '$c': TEA pid=$N"
  if [ -n "$N" ]; then ps -o pid=,ppid=,uid=,comm= -p $N; sudo $P one user/$U/com.apple.TrustEvaluationAgent | grep -E 'DOMAINPART|"PID"|"PPID"'; break; fi
done
echo "##### done"
exit 0
