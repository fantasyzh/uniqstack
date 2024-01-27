# uniqstack

fast pstack + uniqstack for linux, use libunwind.

# How to build

## libunwind

for static linking, clone https://github.com/libunwind/libunwind, and build from source.

However, to avoid repeatedly read proc maps in multi-thread process, used a hack `init_global_proc_map` from
https://github.com/fantasyzh/libunwind  fork repo.

## compile

```
libunwind_path=/usr/local
g++ -o uniqstack --std=gnu++11 -g uniqstack.cpp -pthread -I$libunwind_path/include/ -L$libunwind_path/lib/ -Wl,-Bstatic -lunwind-ptrace  -lunwind-x86_64 -lunwind -Wl,-Bdynamic
```
