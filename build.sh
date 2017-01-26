#!/bin/bash

rm -f cfi_Os cfi_O0  *.o

BASE=/usr/local/osquery
CC=${BASE}/bin/clang++
BLACKLIST="`pwd`/blacklist/cfi_blacklist.txt"

ARGS="-g -std=c++14 -stdlib=libstdc++ -Qunused-arguments -Wstrict-aliasing -Wno-missing-field-initializers -Wno-unused-local-typedef -Wno-deprecated-register -Wno-unknown-warning-option -Wnon-virtual-dtor -Wchar-subscripts -Wpointer-arith -Woverloaded-virtual -Wformat -Wformat-security -Werror=format-security -Wabi-tag -fpermissive -fstack-protector-all -pipe -fdata-sections -ffunction-sections -fsanitize-blacklist=${BLACKLIST} -flto -fsanitize=cfi -fsanitize-cfi-cross-dso -fno-sanitize-trap=all -fvisibility=default -D_GLIBCXX_USE_CXX11_ABI=1 -fPIE -fpie -fPIC -fpic -march=x86-64 -mno-avx -Wall -Wextra -Wshadow -pedantic -Wuseless-cast -Wno-c99-extensions -Wno-zero-length-array -Wno-unused-parameter -Wno-gnu-case-range"
LINKARGS=" -fno-sanitize-trap=all -flto -fsanitize=cfi -fsanitize-cfi-cross-dso -fvisibility=default -D_GLIBCXX_USE_CXX11_ABI=1 -fsanitize-blacklist=${BLACKLIST}"
LINKARGS2="-lboost_system-mt -lboost_filesystem-mt -lpthread -static-libstdc++"

${CC}  -I${BASE}/include -I. ${ARGS} -c -o config.o config.cpp
${CC}  -I${BASE}/include -I. -Os ${ARGS} -c -o registry_Os.o registry.cpp
${CC}  -I${BASE}/include -I. -O0 ${ARGS} -c -o registry_O0.o registry.cpp
${CC}  -L${BASE}/lib -I${BASE}/include -I. ${LINKARGS} -o cfi_Os config.o registry_Os.o ${LINKARGS2}
${CC}  -L${BASE}/lib -I${BASE}/include -I. ${LINKARGS} -o cfi_O0 config.o registry_O0.o ${LINKARGS2}
