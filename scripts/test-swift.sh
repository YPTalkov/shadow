#!/bin/sh
set -eu

frameworks=/Library/Developer/CommandLineTools/Library/Developer/Frameworks
interop=/Library/Developer/CommandLineTools/Library/Developer/usr/lib

if [ -d "$frameworks/Testing.framework" ] && [ -f "$interop/lib_TestingInterop.dylib" ]; then
  exec swift test \
    -Xswiftc "-F$frameworks" \
    -Xlinker "-F$frameworks" \
    -Xlinker -rpath -Xlinker "$frameworks" \
    -Xlinker -rpath -Xlinker "$interop"
fi

exec swift test
