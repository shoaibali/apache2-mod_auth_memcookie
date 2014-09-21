#!/bin/sh

rm -f ../libapache2-mod-auth-memcookie_*_amd64.*

# clean 
debclean
fakeroot make -f debian/rules clean


# build 
debuild  -rfakeroot -us -uc -b -tc --lintian-opts '-V' # just to get lintian to shutup
