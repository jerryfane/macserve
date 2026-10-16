#!/bin/bash
# Scratch native probe 3 for v0.1.10 (do not merge).
U=$(id -u)
go build -o /tmp/envprobe ./scratch/envprobe || exit 1
P=/tmp/envprobe
launchctl kickstart user/$U/com.apple.TrustEvaluationAgent; sleep 2
sudo $P dump gui/$U user/$U > /tmp/d0.json
echo "##### adoption rule check (clean)"
$P check < /tmp/d0.json
echo "##### anchors"
jq -r '.[] | select(.Target|test("com.apple.(Dock|Finder|TrustEvaluationAgent)$")) | .Target + " path=" + .Path + " type=" + .Type + " program=" + .Program + " exec=" + .Exec + " args=" + (.Arguments|join(",")) + " argv=" + (.Argv|join(","))' /tmp/d0.json
echo "##### after setenv, newly kickstarted agents"
launchctl setenv PROBE_ENV poisoned
for l in com.apple.corespeechd com.apple.Finder; do launchctl kickstart -k gui/$U/$l; done
launchctl kickstart -k user/$U/com.apple.TrustEvaluationAgent
sleep 3
sudo $P dump gui/$U user/$U > /tmp/d1.json
$P check < /tmp/d1.json | grep -E '^REF|^STAT|RULE'
launchctl unsetenv PROBE_ENV
echo "##### done"
exit 0
