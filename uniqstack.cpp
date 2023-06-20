// build command:
// g++ -o uniqstack --std=gnu++11 -g uniqstack.cpp -pthread -I$libunwind_path/usr/local/include/ -L$libunwind_path/usr/local/lib -Wl,-Bstatic  -lunwind-ptrace  -lunwind-x86_64 -lunwind -lunwind-ptrace -Wl,-Bdynamic
#include <libunwind.h>
#include <libunwind-ptrace.h>
#include <libunwind_global_proc_maps.h>
#include <cxxabi.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <map>
#include <set>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <algorithm>

using namespace std;

static const int kMaxBacktraceDepth = 100;

std::mutex cacheLock;
map<long, string> symbolCache;

// for profiling
long get_timestamp_us()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec*1000000 + ts.tv_nsec/1000;
}

void get_proc_maps(pid_t pid, vector<pair<pair<long, long>, string> >& proc_maps)
{
    char proc_maps_path[32];
    snprintf(proc_maps_path, sizeof(proc_maps_path), "/proc/%d/maps", pid);

    ifstream ifs(proc_maps_path);

    while (ifs)
    {
        long addr_begin, addr_end;
        string file;
        string addr_range;
        string perms;
        string ignore;

        string line;
        std::getline(ifs, line);

        stringstream ss(line);
        ss >> addr_range >> perms >> ignore >> ignore >> ignore;
        if (perms == "r-xp")
        {
            ss >> file;
        }
        else
        {
            continue;
        }
        size_t pos = addr_range.find('-');
        addr_begin = strtoul(addr_range.substr(0, pos).c_str(), NULL, 16);
        addr_end = strtoul(addr_range.substr(pos + 1).c_str(), NULL, 16);
        proc_maps.push_back(make_pair(make_pair(addr_begin, addr_end), file));

        //fprintf(stderr, "%lx - %lx %s\n", addr_begin, addr_end, file.c_str());
    }

    ifs.close();
}

bool get_file_offset_from_maps(long ip, const vector<pair<pair<long, long>, string> >& proc_maps, string& file, long& offset)
{
    for (auto& mapping : proc_maps)
    {
        if (ip >= mapping.first.first && ip <= mapping.first.second)
        {
            file = mapping.second;
            bool is_binary = mapping.first.first == 0x400000;
            offset = is_binary? ip : ip - mapping.first.first;
            return true;
        }
    }
    return false;
}

vector<string> get_symbol_from_file_offset(string file, vector<long> offsets)
{
    vector<string> ret;
    char cmd[4096];
    int n = snprintf(cmd, sizeof(cmd), "addr2line -p -i -f -C -e %s", file.c_str());
    for (long offset : offsets)
    {
        n += snprintf(cmd+n, sizeof(cmd)-n, " 0x%lx", offset);
    }
    //fprintf(stderr, "addr2line cmd: %s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (!fp)
    {
        fprintf(stderr, "run addr2line cmd error %s\n", cmd);
        return ret;
    }
    vector<char> output(4096);
    const string INLINE_PREFIX = " (inlined by) ";
    int offsetIdx = 0;
    while (fgets(output.data(), output.size(), fp))
    {
        //fprintf(stderr, "%d %s", offsetIdx, output.data());
        int len = strlen(output.data()) - 1; //strip \n
        string symbol(output.data(), len);
        if (strncmp(output.data(), INLINE_PREFIX.c_str(), INLINE_PREFIX.length()) == 0)
        {
            symbol = symbol.substr(INLINE_PREFIX.length());
            ret.back() = symbol;
        }
        else
        {
            if (!ret.empty())
            {
                vector<char> extrabuf(4096);
                snprintf(extrabuf.data(), extrabuf.size(), " %s+0x%lx", file.c_str(), offsets[offsetIdx]);
                ret.back() += string(extrabuf.data());
                offsetIdx += 1;
            }
            ret.push_back(symbol);
        }
    }
    fclose(fp);
    if (!ret.empty())
    {
        char extrabuf[512];
        snprintf(extrabuf, sizeof(extrabuf), " %s+0x%lx", file.c_str(), offsets[offsetIdx]);
        ret.back() += string(extrabuf);
        offsetIdx += 1;
    }
    if (offsetIdx != offsets.size())
    {
        fprintf(stderr, "addr2line not enough output lines, idx: %d, offsets: %d\n", offsetIdx, offsets.size());
        ret.clear();
        return ret;
    }

    return ret;
}

pid_t ptrace_attach(pid_t pid)
{
#if 0
    long ret_ptrace_attach = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
#else
    long ret_ptrace_attach = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
    if (ret_ptrace_attach == 0)
    {
        ret_ptrace_attach = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    }
#endif
    if (ret_ptrace_attach != 0)
    {
        if (errno == ESRCH)
        {
            return 0;
        }
        else
        {
            perror("ptrace attach");
            exit(1);
        }
    }
    else
    {
        return pid;
    }
}

bool get_backtrace(pid_t pid, vector<long>& stack, map<long, string>& symbolCache, std::mutex& cacheLock)
{
    bool ok = false;
    unw_cursor_t cursor;
    unw_word_t ip, sp;

    unw_addr_space_t addrspace = unw_create_addr_space(&_UPT_accessors, 0);
    unw_set_caching_policy(addrspace, UNW_CACHE_GLOBAL);

    do
    {
        int status;
        pid_t gotpid = waitpid(pid, &status, __WALL);
        if (gotpid == -1)
        {
            perror("waitpid");
            break;
        }
        if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP))
        {
            fprintf(stderr, "waitpid stop status not SIGTRAP: %d\n", status);
        }

        void *arg = _UPT_create(pid);
        assert(arg);

        int err = unw_init_remote(&cursor, addrspace, arg);
        if (err != 0)
        {
            fprintf(stderr, "unw_init_remote err: %d\n", err);
            break;
        }

        int depth = 0;
        while (++depth <= kMaxBacktraceDepth && unw_step(&cursor) > 0) {
            unw_get_reg(&cursor, UNW_REG_IP, &ip);
            //unw_get_reg(&cursor, UNW_REG_SP, &sp);
            stack.push_back(ip);
            cacheLock.lock();
            bool newIp = (symbolCache.find(ip) == symbolCache.end());
            cacheLock.unlock();
            if (newIp)
            {
                char buf[512];
                unw_word_t procoff;
                int err = unw_get_proc_name(&cursor, buf, sizeof(buf), &procoff);

                if (err)
                {
                    //fprintf(stderr, "unw_get_proc_name errorCode: %d ip:%lx\n", err, ip);
                    cacheLock.lock();
                    symbolCache[ip] = string();
                    cacheLock.unlock();
                }
                else
                {
                    size_t buf2len = 512;
                    char *buf2 = (char*)malloc(buf2len);
                    int status;
                    buf2 = abi::__cxa_demangle(buf, buf2, &buf2len, &status);
                    cacheLock.lock();
                    symbolCache[ip] = buf2? buf2 : buf;
                    cacheLock.unlock();
                    free(buf2);
                }
            }
        }
        ok = true;
        //_UPT_resume(addrspace, &cursor, arg);
        _UPT_destroy(arg);
    } while(0);

    long ret_ptrace_detach = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (ret_ptrace_detach != 0)
    {
        perror("ptrace detach");
    }
    return ok;
}

void Usage()
{
    fprintf(stderr, "Usage: unistack <pid> [<tid> ...]\n");
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        Usage();
        return 1;
    }

    int optind = 1;

    int pid = atoi(argv[optind]);
    if (pid <= 0)
    {
        fprintf(stderr, "Invalid pid '%d'\n", pid);
        return 1;
    }

    optind++;

    std::set<int> tids;
    for (int i = optind; i < argc; i++)
    {
        int tid = atoi(argv[i]);
        if (tid <= 0)
        {
            fprintf(stderr, "Invalid tid '%d'\n", tid);
            return 1;
        }
        tids.insert(tid);
    }

    // get proc maps
    vector<pair<pair<long, long>, string> > proc_maps;
    get_proc_maps(pid, proc_maps);

    if (proc_maps.empty())
    {
        fprintf(stderr, "failed to get proc maps\n");
        return 1;
    }

    // list threads
    char proc_task[32];
    snprintf(proc_task, sizeof(proc_task), "/proc/%d/task/", pid);
    DIR *dir = opendir(proc_task);
    if (!dir)
    {
        perror("opendir");
        exit(1);
    }

    map<int, vector<long> > stacks;

    vector<int> threads;
    while (1)
    {
        struct dirent entry, *rentry;
        int ret_readdir = readdir_r(dir, &entry, &rentry);
        if (ret_readdir != 0)
        {
            perror("readdir_r");
            exit(1);
        }

        // end
        if (!rentry)
        {
            break;
        }

        const char *thread_pid = entry.d_name;
        assert(thread_pid);

        if (strcmp(thread_pid, ".") == 0 || strcmp(thread_pid, "..") == 0)
        {
            continue;
        }

        int tpid = atoi(thread_pid);
        if (tpid <= 0)
        {
            fprintf(stderr, "skip proc task entry '%s'\n", thread_pid);
            continue;
        }

        if (tids.empty() || tids.find(tpid) != tids.end())
        {
            threads.push_back(tpid);
        }

        // TODO  get thread status  (before or after traced?)
        // TODO  get kernel stack
    }

    closedir(dir);

    init_global_proc_map(pid);

    time_t ptrace_start = time(NULL);

    struct ThreadWork
    {
        std::thread t;
        vector<int> threadsLocal;
        map<int, vector<long> > stacksLocal;

        void run()
        {
            for (size_t i = 0; i < threadsLocal.size(); i++)
            {
                int tpid = threadsLocal[i];
                threadsLocal[i] = ptrace_attach(tpid);
            }
            for (size_t i = 0; i < threadsLocal.size(); i++)
            {
                int tpid = threadsLocal[i];

                if (tpid == 0) continue; // thread not exist

                vector<long> stack;
                if (get_backtrace(tpid, stack, symbolCache, cacheLock))
                {
                    stacksLocal[tpid] = stack;
                }
            }
        }
    };

    int NUM_THREADS = threads.size()/50 + 1;
    vector<ThreadWork> workers(NUM_THREADS);
    for (size_t i = 0; i < threads.size(); i++)
    {
        int tpid = threads[i];

        if (tpid == 0) continue; // thread not exist
        int idx = i % NUM_THREADS;
        workers[idx].threadsLocal.push_back(tpid);
    }
    if (NUM_THREADS == 1)
    {
        workers[0].run();
        stacks = std::move(workers[0].stacksLocal);
    }
    else
    {
        for (int i = 0; i < NUM_THREADS; i++)
        {
            workers[i].t = std::thread(&ThreadWork::run, &workers[i]);
        }
        for (int i = 0; i < NUM_THREADS; i++)
        {
            workers[i].t.join();
            stacks.insert(workers[i].stacksLocal.begin(), workers[i].stacksLocal.end());
         }
    }

    fprintf(stderr, "Finish ptrace %d threads in %d seconds.\n", threads.size(), time(NULL)-ptrace_start);

    set<long> ips;

    // do unique: group pids by stack
    map<vector<long>, vector<int> > stack2pids;
    for (auto& t : stacks)
    {
        stack2pids[t.second].push_back(t.first);

        for (auto& ip: t.second)
        {
            ips.insert(ip);
        }
    }

    map<string, pair<vector<long>, vector<long> > > file2ips; // <ips, offsets>

    for (auto& ip : ips)
    {
        string file;
        long offset;
        if (get_file_offset_from_maps(ip, proc_maps, file, offset))
        {
            if (!symbolCache[ip].empty())
            {
                char extrabuf[512];
                snprintf(extrabuf, sizeof(extrabuf), " %s+0x%lx", file.c_str(), offset);
                symbolCache[ip] += extrabuf;
            }
            else
            {
                file2ips[file].first.push_back(ip);
                file2ips[file].second.push_back(offset);
            }
        }
    }

    if (!file2ips.empty())
    {
        fprintf(stderr, "To translate %d unknown addresses using addr2line\n", file2ips.size());
        for (auto& file2ipsItem : file2ips)
        {
            vector<string> symbols = get_symbol_from_file_offset(file2ipsItem.first, file2ipsItem.second.second);
            for (size_t i = 0; i < symbols.size(); i++)
            {
                //fprintf(stderr, "get symbol: %s 0x%lx\n", symbols[i].c_str(), file2ipsItem.second.first[i]);
                symbolCache[file2ipsItem.second.first[i]] = symbols[i];
            }
        }
    }

    // order by thread number desc
    vector<pair<vector<long>, vector<int>> > stack2pids_ordered(stack2pids.begin(), stack2pids.end());
    std::sort(stack2pids_ordered.begin(), stack2pids_ordered.end(), [](
                const pair<vector<long>, vector<int>>& a, const pair<vector<long>, vector<int>>& b) { return a.second.size() > b.second.size(); });
    for (auto& s : stack2pids_ordered)
    {
        if (s.second.size() == 1)
        {
            printf("Thread %d:\n", s.second.front());
        }
        else
        {
            printf("Thread {%d} (", s.second.size());
            bool first = true;
            for (auto& t : s.second)
            {
                if (first)
                {
                    printf("%d", t);
                    first = false;
                }
                else
                {
                    printf(",%d", t);
                }
            }
            printf("):\n");
        }
        int idx = 0;
        for (auto& ip : s.first)
        {
            string symbol = symbolCache[ip];

            if (symbol.empty())
            {
                symbol = "??";
            }

            printf("#%d 0x%lx %s\n", idx, ip, symbol.c_str());
            idx++;
        }
    }
}
