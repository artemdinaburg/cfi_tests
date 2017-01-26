# CFI Strangeness

Build using `build.sh`. Edit the script to set `CC` and the system path (`BASE`)

The O0 optimized version does not violate CFI, the Os version does. Both use the same blacklist (`type:*`)

Output below:

     $ ./cfi_O0
     Starting it up...
     
     Finishing...
     
     $ ./cfi_Os
     Starting it up...
     /usr/local/osquery/Cellar/gcc/5.3.0/lib64/gcc/x86_64-unknown-linux-gnu/5.3.0/../../../../include/c++/5.3.0/ostream:113:9: runtime error: control flow integrity check for type 'std::basic_ostream<char> &(std::basic_ostream<char> &)' failed during indirect function call
     (/store/artem/git/cfi_test/cfi_Os+0xe77e9): note: (unknown) defined here
     SUMMARY: CFI: undefined-behavior /usr/local/osquery/Cellar/gcc/5.3.0/lib64/gcc/x86_64-unknown-linux-gnu/5.3.0/../../../../include/c++/5.3.0/ostream:113:9 in
