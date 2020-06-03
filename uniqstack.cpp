// build command:
// g++ -o uniqstack --std=gnu++11 -g uniqstack.cpp -I$libunwind_path/usr/local/include/ -L$libunwind_path/usr/local/lib -Wl,-Bstatic  -lunwind-ptrace  -lunwind-x86_64 -lunwind -lunwind-ptrace -Wl,-Bdynamic
#include <libunwind.h>
#include <libunwind-ptrace.h>
#include <cxxabi.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <map>
#include <set>
#include <vector>
#include <fstream>
#include <sstream>

using namespace std;

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

bool get_file_offset_from_maps(long ip, const vector<pair<pair<long, long>, string> >& proc_maps, string& file, long& offset, bool& is_binary)
{
    for (auto& mapping : proc_maps)
    {
        if (ip >= mapping.first.first && ip <= mapping.first.second)
        {
            file = mapping.second;
            is_binary = mapping.first.first == 0x400000;
            offset = is_binary? ip : ip - mapping.first.first;
            return true;
        }
    }
    return false;
}

string get_symbol_from_file_offset(string file, long offset, bool is_binary)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "addr2line -p -f -C -e %s %s 0x%lx", file.c_str(), ""/*is_binary? "" : "-j .text"*/, offset);
    //fprintf(stderr, "addr2line cmd: %s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (!fp)
    {
        return "<addr2line error>";
    }
    vector<char> output(512);
    fgets(output.data(), output.size(), fp);
    fclose(fp);
    string symbol(output.data());
    if (symbol[symbol.size() - 1] = '\n') symbol.resize(symbol.size() - 1);

    return symbol;
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

bool get_backtrace(pid_t pid, vector<pair<long, string> >& stack)
{
    bool ok = false;
    unw_cursor_t cursor;
    unw_word_t ip, sp;

    unw_addr_space_t addrspace = unw_create_addr_space(&_UPT_accessors, 0);

    //ptrace_attach(pid);

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
            fprintf(stderr, "waitpid stop status not SIGTRAP: %d", status);
        }

        void *arg = _UPT_create(pid);
        assert(arg);

        int err = unw_init_remote(&cursor, addrspace, arg);
        if (err != 0)
        {
            fprintf(stderr, "unw_init_remote err: %d\n", err);
            break;
        }

        //printf("Thread %d\n", pid); 
        while (unw_step(&cursor) > 0) {
            unw_get_reg(&cursor, UNW_REG_IP, &ip);
            //unw_get_reg(&cursor, UNW_REG_SP, &sp);
            string procname = "??";
            //char buf[256];
            //unw_word_t procoff;
            //unw_get_proc_name(&cursor, buf, sizeof(buf), &procoff);
            //size_t buf2len = 256;
            //char *buf2 = (char*)malloc(buf2len);
            //int status;
            //buf2 = abi::__cxa_demangle(buf, buf2, &buf2len, &status);
            //procname = buf2? buf2 : procname;
            //free(buf2);
            //printf("0x%lx %s\n", ip, procname.c_str()); 
            stack.push_back(make_pair(ip, procname));
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

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: unistack <pid> [<tid> ...]\n");
        return 1;
    }

    int pid = atoi(argv[1]);
    if (pid <= 0)
    {
        fprintf(stderr, "Invalid pid '%d'\n", pid);
        return 1;
    }

    std::set<int> tids;
    for (int i = 2; i < argc; i++)
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

    map<int, vector<pair<long, string> > > stacks;

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

    time_t ptrace_start = time(NULL);

    for (size_t i = 0; i < threads.size(); i++)
    {
        int tpid = threads[i];
        threads[i] = ptrace_attach(tpid);
    }

    for (size_t i = 0; i < threads.size(); i++)
    {
        int tpid = threads[i];

        if (tpid == 0) continue; // thread not exist

        vector<pair<long, string> > stack;
        if (get_backtrace(tpid, stack))
        {
            stacks[tpid] = stack;
        }
    }

    fprintf(stderr, "Finish ptrace %d threads in %d seconds.\n", threads.size(), time(NULL)-ptrace_start);

    // do unique: group pids by stack
    map<vector<pair<long, string> >, vector<int> > stack2pids;
    for (auto& t : stacks)
    {
        stack2pids[t.second].push_back(t.first);
    }

    map<long, string> symbolCache;

    for (auto& s : stack2pids)
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
            string symbol = "<unknown symbol>";
            string file;
            long offset;
            bool is_binary;

            if (symbolCache.find(ip.first) != symbolCache.end())
            {
                symbol = symbolCache[ip.first];
            }
            else
            {
                if (get_file_offset_from_maps(ip.first, proc_maps, file, offset, is_binary))
                {
                    symbol = get_symbol_from_file_offset(file, offset, is_binary);
                    symbolCache[ip.first] = symbol;
                }
            }

            printf("#%d 0x%lx %s %s+0x%lx\n", idx, ip.first, symbol.c_str(), file.c_str(), offset);
            idx++;
        }
    }
}
