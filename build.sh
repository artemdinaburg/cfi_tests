#!/bin/bash

rm -f cfi_blacklist  *.o

BLACKLIST="`pwd`/blacklist/cfi_blacklist.txt"
ARGS="-std=c++14 -stdlib=libstdc++ -Qunused-arguments -Wstrict-aliasing -Wno-missing-field-initializers -Wno-unused-local-typedef -Wno-deprecated-register -Wno-unknown-warning-option -Wnon-virtual-dtor -Wchar-subscripts -Wpointer-arith -Woverloaded-virtual -Wformat -Wformat-security -Werror=format-security -Wabi-tag -fpermissive -fstack-protector-all -pipe -fdata-sections -ffunction-sections -fsanitize-blacklist=${BLACKLIST} -flto -fsanitize=cfi -fsanitize-cfi-cross-dso -fno-sanitize-trap=all -fvisibility=default -D_GLIBCXX_USE_CXX11_ABI=1 -Os -fPIE -fpie -fPIC -fpic -march=x86-64 -mno-avx -Wall -Wextra -Wshadow -pedantic -Wuseless-cast -Wno-c99-extensions -Wno-zero-length-array -Wno-unused-parameter -Wno-gnu-case-range"
LINKARGS=" -fno-sanitize-trap=all -flto -fsanitize=cfi -fsanitize-cfi-cross-dso -fvisibility=default -D_GLIBCXX_USE_CXX11_ABI=1 -fsanitize-blacklist=${BLACKLIST}"
LINKARGS2="-lboost_system-mt -lboost_filesystem-mt -lpthread -static-libstdc++"
/usr/local/osquery/bin/clang++  -I/usr/local/osquery/include -I. ${ARGS} -c -o config.o config.cpp
/usr/local/osquery/bin/clang++  -I/usr/local/osquery/include -I. ${ARGS} -c -o registry.o registry.cpp
/usr/local/osquery/bin/clang++  -L/usr/local/osquery/lib -I/usr/local/osquery/include -I. ${LINKARGS} -o cfi_blacklist config.o registry.o ${LINKARGS2}
