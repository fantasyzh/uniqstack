# uniqstack

fast pstack + uniqstack for linux, use libunwind.

# How to build

## libunwind

for static linking, need download source from https://www.nongnu.org/libunwind/download.html , and build from source.

## compile

```
libunwind_path=/usr/local
g++ -o uniqstack --std=gnu++11 -g uniqstack.cpp -pthread -I$libunwind_path/include/ -L$libunwind_path/lib/ -Wl,-Bstatic -lunwind-ptrace  -lunwind-x86_64 -lunwind -Wl,-Bdynamic
```
