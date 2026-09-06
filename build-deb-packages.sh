#!/bin/bash
#-b → build binary packages only
#-us → don't sign the source package
#-uc → don't sign the changes file
cd "$(dirname "$(realpath "$0")")"

docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  -v "$(dirname "$PWD"):/build" \
  -w "/build/$(basename "$PWD")" \
  vyos/vyos-build:current  dpkg-buildpackage -us -uc -b

