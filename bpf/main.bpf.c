//go:build ignore
#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define PF_KTHREAD 0x00200000

struct enter_data_t {
    char filename[256];
    u64 flags;
    u64 count;
    s64 fd;  // Explicit fd field for I/O syscalls
};

// Network socket tracking data
struct socket_data_t {
    u32 src_ip;
    u32 dest_ip;
    u32 src_ipv6[4];
    u32 dest_ipv6[4];
    u16 src_port;
    u16 dest_port;
    u16 sa_family;
    u8 protocol;  // IPPROTO_TCP, IPPROTO_UDP
};

// Accept args storage (replaces raw pointer)
struct accept_args_t {
    u16 sa_family;
    u16 port;
    u32 ipv4;
    u32 ipv6[4];
};

// Event type classification
enum event_type {
    EV_FS = 1,    // Filesystem event
    EV_NET = 2,   // Network event
    EV_PROC = 3,  // Process event
};

// Helper functions for safe IP address copying
static __always_inline void copy_ipv4_from_sockaddr(u32 *dest, struct sockaddr_in *addr) {
    if (!dest || !addr) return;
    u32 raw_ip;
    bpf_probe_read_user(&raw_ip, sizeof(raw_ip), &addr->sin_addr.s_addr);
    *dest = bpf_ntohl(raw_ip);
}

static __always_inline void copy_ipv6_from_sockaddr(u32 dest[4], struct sockaddr_in6 *addr) {
    if (!dest || !addr) return;
    bpf_probe_read_user(dest, 16, &addr->sin6_addr);
}

static __always_inline u16 copy_port_from_sockaddr(struct sockaddr *addr, u16 family) {
    if (!addr) return 0;
    u16 port = 0;
    if (family == 2) {  // AF_INET
        bpf_probe_read_user(&port, sizeof(port), &((struct sockaddr_in *)addr)->sin_port);
    } else if (family == 10) {  // AF_INET6
        bpf_probe_read_user(&port, sizeof(port), &((struct sockaddr_in6 *)addr)->sin6_port);
    }
    return bpf_ntohs(port);
}

struct so_event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 process_start_time;  // For correlation with PCAP
    char comm[64];
    char syscall[32];
    char filename[256];
    s64 fd;
    u64 flags;
    s64 ret;
    u8 event_type;  // Event classification

    // Network fields (enhanced)
    u32 src_ip;
    u32 dest_ip;
    u32 src_ipv6[4];
    u32 dest_ipv6[4];
    u16 src_port;
    u16 dest_port;
    u16 sa_family;
    u8 protocol;  // TCP/UDP/etc
    u8 socket_type;  // SOCK_STREAM/SOCK_DGRAM

    // I/O fields
    u64 count;
    s64 bytes_rw;
};

const struct so_event *__unused __attribute__((unused));

// --- MAPS ---
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct so_event);
} event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct enter_data_t);
} open_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct enter_data_t);
} write_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct enter_data_t);
} read_data SEC(".maps");

// Map to track socket FD to network info (for correlation)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // pid_tgid << 32 | fd
    __type(value, struct socket_data_t);
} socket_map SEC(".maps");

// Whitelist rule structure (IP + Port combination)
struct whitelist_rule {
    u32 ip;      // IPv4 address in network byte order
    u16 port;    // Port in network byte order
    u16 padding; // Alignment
};

// Whitelist map for combined IP+Port rules
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);  // Max 64 whitelist rules
    __type(key, u64);  // Index
    __type(value, struct whitelist_rule);
} whitelist_rules SEC(".maps");

// Map to track connect enter data
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct socket_data_t);
} connect_data SEC(".maps");

// Map for user-space configurable ignored process names
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);  // Max 128 ignored process names
    __type(key, char[64]);     // Process name (comm)
    __type(value, u8);         // 1 = ignore
} ignored_comms SEC(".maps");

// --- MAP FOR ACCEPT CORRELATION ---
// Stores copied sockaddr data from sys_enter_accept/4 to read it in sys_exit
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct accept_args_t);
} active_accepts SEC(".maps");

// -------------------------------------------------------------------------
// OPTIMIZED FILTERING LOGIC
// -------------------------------------------------------------------------

// Filter based on Process Name (Comm) - Called EARLY
static __always_inline int should_drop_comm(char *c) {
    // Check if this comm is in the ignored_comms map
    u8 *ignored = bpf_map_lookup_elem(&ignored_comms, c);
    if (ignored && *ignored == 1) {
        return 1;
    }

    // Smart kworker filter - Only drop if it is ACTUALLY a kernel thread (PF_KTHREAD).
    // Keeps malware named "kworker".
    if (c[0]=='k' && c[1]=='w' && c[2]=='o' && c[3]=='r' && c[4]=='k') {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        u32 flags = 0;
        BPF_CORE_READ_INTO(&flags, task, flags);
        if (flags & PF_KTHREAD) return 1;
    }

    return 0;
}

// Filter based on File/Path - Called LATE (in submit)
static __always_inline int should_drop_file(struct so_event *e) {
    char *f = e->filename;
    char *sys = e->syscall;
    if (f[0] == 0) return 0;
    if (sys[0] == 'e' && sys[1] == 'x' && sys[2] == 'e' && sys[3] == 'c') return 0;
    if (f[0]=='/' && f[1]=='u' && f[2]=='s' && f[3]=='r' && f[4]=='/' &&
        f[5]=='l' && f[6]=='i' && f[7]=='b') return 1;
    if (f[0]=='/' && f[1]=='l' && f[2]=='i' && f[3]=='b') return 1;
    if (f[0]=='/' && f[1]=='s' && f[2]=='y' && f[3]=='s' && f[4]=='/') return 1;
    if (f[0]=='/' && f[1]=='p' && f[2]=='r' && f[3]=='o' && f[4]=='c') return 1;
    if (f[0]=='/' && f[1]=='d' && f[2]=='e' && f[3]=='v' && f[4]=='/') {
        if (f[5]=='n' && f[6]=='u' && f[7]=='l' && f[8]=='l') return 1;
        if (f[5]=='u' && f[6]=='r' && f[7]=='a' && f[8]=='n') return 1;
        if (f[5]=='z' && f[6]=='e' && f[7]=='r' && f[8]=='o') return 1;
        if (f[5]=='p' && f[6]=='t' && f[7]=='s' && f[8]=='/') return 1;
    }
    if (f[0]=='/' && f[1]=='r' && f[2]=='u' && f[3]=='n' && f[4]=='/') return 1;
    return 0;
}

static __always_inline struct so_event* init_event() {
    u32 zero = 0;
    struct so_event *event = bpf_map_lookup_elem(&event_heap, &zero);
    if (!event) return NULL;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    if (should_drop_comm(event->comm)) return NULL;

    event->uid = bpf_get_current_uid_gid();
    event->timestamp = bpf_ktime_get_ns();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&event->ppid, task, real_parent, tgid);
    BPF_CORE_READ_INTO(&event->process_start_time, task, start_time);

    event->filename[0] = 0;
    event->event_type = 0;
    event->src_ip = 0;
    event->dest_ip = 0;
    event->src_port = 0;
    event->dest_port = 0;
    event->sa_family = 0;
    event->protocol = 0;
    event->socket_type = 0;
    event->count = 0;
    event->bytes_rw = 0;
    __builtin_memset(event->src_ipv6, 0, sizeof(event->src_ipv6));
    __builtin_memset(event->dest_ipv6, 0, sizeof(event->dest_ipv6));
    return event;
}

static __always_inline bool is_whitelisted_network(u32 ip, u16 port) {
    struct whitelist_rule *rule;
    u64 idx;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        idx = i;
        rule = bpf_map_lookup_elem(&whitelist_rules, &idx);
        if (rule && rule->ip == ip && rule->port == port) return true;
    }
    return false;
}

// Check if this is the system-monitor process (collector itself)
static __always_inline bool is_collector_process(char *comm) {
    // Check for "system-monitor"
    if (comm[0]=='s' && comm[1]=='y' && comm[2]=='s' && comm[3]=='t' && comm[4]=='e' && comm[5]=='m' &&
        comm[6]=='-' && comm[7]=='m' && comm[8]=='o' && comm[9]=='n' && comm[10]=='i' && comm[11]=='t' &&
        comm[12]=='o' && comm[13]=='r') {
        return true;
    }
    return false;
}

// Check if event should be dropped due to whitelist
// Only applies whitelist to the collector process itself to prevent attacker evasion
static __always_inline bool should_drop_network(struct so_event *event) {
    // Only apply whitelist if this is the collector process
    if (!is_collector_process(event->comm)) {
        return false;
    }

    if (event->syscall[0] == 'c' && event->syscall[1] == 'o' && event->syscall[2] == 'n') {
        if (event->sa_family == 2 && is_whitelisted_network(event->dest_ip, event->dest_port)) return true;
    } else if (event->syscall[0] == 'b' && event->syscall[1] == 'i' && event->syscall[2] == 'n') {
        if (event->sa_family == 2 && is_whitelisted_network(event->src_ip, event->src_port)) return true;
    } else if (event->syscall[0] == 's' && event->syscall[1] == 'e' && event->syscall[2] == 'n') {
        if (event->sa_family == 2 && is_whitelisted_network(event->dest_ip, event->dest_port)) return true;
    } else if (event->syscall[0] == 'r' && event->syscall[1] == 'e' && event->syscall[2] == 'c') {
        if (event->sa_family == 2 && is_whitelisted_network(event->src_ip, event->src_port)) return true;
    }
    return false;
}

static __always_inline void submit(void *ctx, struct so_event *event) {
    if (should_drop_file(event)) return;
    if (should_drop_network(event)) return;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
}

// --- ARG STRUCTS ---
struct args_execve { struct trace_entry ent; long int id; const char * filename; const char *const * argv; const char *const * envp; };
struct args_openat { struct trace_entry ent; long int id; long int dfd; const char * filename; long int flags; long int mode; };
struct open_how_local { u64 flags; u64 mode; u64 resolve; };
struct args_openat2 { struct trace_entry ent; long int id; long int dfd; const char * filename; struct open_how_local * how; size_t size; };
struct args_write { struct trace_entry ent; long int id; long int fd; const char * buf; size_t count; };
struct args_read { struct trace_entry ent; long int id; long int fd; char * buf; size_t count; };
struct args_unlinkat { struct trace_entry ent; long int id; long int dfd; const char * pathname; int flag; };
struct args_connect { struct trace_entry ent; long int id; long int fd; struct sockaddr * uservaddr; int addrlen; };
struct args_accept { struct trace_entry ent; long int id; long int fd; struct sockaddr * upeer_sockaddr; int * upeer_addrlen; long int flags; };
struct args_bind { struct trace_entry ent; long int id; long int fd; struct sockaddr * umyaddr; int addrlen; };
struct args_listen { struct trace_entry ent; long int id; long int fd; int backlog; };
struct args_socket { struct trace_entry ent; long int id; int family; int type; int protocol; };
struct args_sendto { struct trace_entry ent; long int id; long int fd; void * buff; size_t len; unsigned int flags; struct sockaddr * addr; int addr_len; };
struct args_recvfrom { struct trace_entry ent; long int id; long int fd; void * ubuf; size_t size; unsigned int flags; struct sockaddr * addr; int * addr_len; };
struct args_exit { struct trace_entry ent; long int id; long int ret; };

// --- PROBES ---

SEC("tp/syscalls/sys_enter_execve")
int sys_enter_execve(struct args_execve *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    event->event_type = EV_PROC;
    __builtin_memcpy(event->syscall, "execve", 7);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->filename);
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int sys_enter_openat(struct args_openat *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), ctx->filename);
    data.flags = ctx->flags;
    bpf_map_update_elem(&open_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat2")
int sys_enter_openat2(struct args_openat2 *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    struct open_how_local how = {};
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), ctx->filename);
    bpf_probe_read_user(&how, sizeof(struct open_how_local), ctx->how);
    data.flags = how.flags;
    bpf_map_update_elem(&open_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int sys_exit_openat(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&open_data, &id);
    if (!data) return 0;
    struct so_event *event = init_event();
    if (event) {
        event->event_type = EV_FS;
        __builtin_memcpy(event->syscall, "openat", 7);
        __builtin_memcpy(event->filename, data->filename, sizeof(event->filename));
        event->flags = data->flags;
        event->ret = ctx->ret;
        submit(ctx, event);
    }
    bpf_map_delete_elem(&open_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat2")
int sys_exit_openat2(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&open_data, &id);
    if (!data) return 0;
    struct so_event *event = init_event();
    if (event) {
        event->event_type = EV_FS;
        __builtin_memcpy(event->syscall, "openat2", 8);
        __builtin_memcpy(event->filename, data->filename, sizeof(event->filename));
        event->flags = data->flags;
        event->ret = ctx->ret;
        submit(ctx, event);
    }
    bpf_map_delete_elem(&open_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int sys_enter_write(struct args_write *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    data.fd = ctx->fd;
    data.count = ctx->count;
    bpf_map_update_elem(&write_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_write")
int sys_exit_write(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&write_data, &id);
    if (!data) return 0;
    if (ctx->ret < 0) { bpf_map_delete_elem(&write_data, &id); return 0; }
    struct so_event *event = init_event();
    if (event) {
        event->event_type = EV_FS;
        __builtin_memcpy(event->syscall, "write", 6);
        event->fd = data->fd;
        event->count = data->count;
        event->bytes_rw = ctx->ret;
        event->ret = ctx->ret;
        submit(ctx, event);
    }
    bpf_map_delete_elem(&write_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int sys_enter_read(struct args_read *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    data.fd = ctx->fd;
    data.count = ctx->count;
    bpf_map_update_elem(&read_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int sys_exit_read(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&read_data, &id);
    if (!data) return 0;
    if (ctx->ret < 4) { bpf_map_delete_elem(&read_data, &id); return 0; } // Filter small reads
    struct so_event *event = init_event();
    if (event) {
        event->event_type = EV_FS;
        __builtin_memcpy(event->syscall, "read", 5);
        event->fd = data->fd;
        event->count = data->count;
        event->bytes_rw = ctx->ret;
        event->ret = ctx->ret;
        submit(ctx, event);
    }
    bpf_map_delete_elem(&read_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int sys_enter_unlinkat(struct args_unlinkat *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    event->event_type = EV_FS;
    __builtin_memcpy(event->syscall, "unlinkat", 9);
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->pathname);
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_vfork")
int sys_enter_vfork(void *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    event->event_type = EV_PROC;
    __builtin_memcpy(event->syscall, "vfork", 6);
    submit(ctx, event);
    return 0;
}

// ===== NETWORK SYSCALLS =====

SEC("tp/syscalls/sys_enter_socket")
int sys_enter_socket(struct args_socket *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    event->event_type = EV_NET;
    __builtin_memcpy(event->syscall, "socket", 7);
    event->sa_family = ctx->family;
    event->socket_type = ctx->type;
    event->protocol = ctx->protocol;
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int sys_enter_connect(struct args_connect *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct socket_data_t sock_data = {};

    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr);
    sock_data.sa_family = family;

    if (family == 2) {  // AF_INET (IPv4)
        struct sockaddr_in addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr);
        sock_data.dest_ip = bpf_ntohl(addr.sin_addr.s_addr);
        sock_data.dest_port = bpf_ntohs(addr.sin_port);
    } else if (family == 10) {  // AF_INET6 (IPv6)
        struct sockaddr_in6 addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr);
        sock_data.dest_port = bpf_ntohs(addr.sin6_port);
        bpf_probe_read_user(&sock_data.dest_ipv6, sizeof(sock_data.dest_ipv6), &addr.sin6_addr);
    }

    bpf_map_update_elem(&connect_data, &id, &sock_data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int sys_exit_connect(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct socket_data_t *sock_data = bpf_map_lookup_elem(&connect_data, &id);
    if (!sock_data) return 0;

    struct so_event *event = init_event();
    if (event) {
        event->event_type = EV_NET;
        __builtin_memcpy(event->syscall, "connect", 8);
        event->sa_family = sock_data->sa_family;
        event->dest_ip = sock_data->dest_ip;
        event->dest_port = sock_data->dest_port;
        __builtin_memcpy(event->dest_ipv6, sock_data->dest_ipv6, sizeof(event->dest_ipv6));
        event->ret = ctx->ret;

        // If connect successful, store socket info for later correlation
        if (ctx->ret >= 0) {
            u64 sock_key = (id & 0xFFFFFFFF00000000ULL) | (u32)ctx->ret;
            bpf_map_update_elem(&socket_map, &sock_key, sock_data, BPF_ANY);
        }

        submit(ctx, event);
    }
    bpf_map_delete_elem(&connect_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_bind")
int sys_enter_bind(struct args_bind *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    event->event_type = EV_NET;
    __builtin_memcpy(event->syscall, "bind", 5);
    event->fd = ctx->fd;

    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), ctx->umyaddr);
    event->sa_family = family;

    if (family == 2) {  // AF_INET
        struct sockaddr_in addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), ctx->umyaddr);
        event->src_ip = bpf_ntohl(addr.sin_addr.s_addr);
        event->src_port = bpf_ntohs(addr.sin_port);
    } else if (family == 10) {  // AF_INET6
        struct sockaddr_in6 addr = {};
        bpf_probe_read_user(&addr, sizeof(addr), ctx->umyaddr);
        event->src_port = bpf_ntohs(addr.sin6_port);
        bpf_probe_read_user(&event->src_ipv6, sizeof(event->src_ipv6), &addr.sin6_addr);
    }

    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_listen")
int sys_enter_listen(struct args_listen *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    event->event_type = EV_NET;
    __builtin_memcpy(event->syscall, "listen", 7);
    event->fd = ctx->fd;
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_accept")
int sys_enter_accept(struct args_accept *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t args = {};

    if (ctx->upeer_sockaddr) {
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), ctx->upeer_sockaddr);
        args.sa_family = family;

        if (family == 2) {  // AF_INET
            struct sockaddr_in addr = {};
            bpf_probe_read_user(&addr, sizeof(addr), ctx->upeer_sockaddr);
            args.ipv4 = bpf_ntohl(addr.sin_addr.s_addr);
            args.port = bpf_ntohs(addr.sin_port);
        } else if (family == 10) {  // AF_INET6
            struct sockaddr_in6 addr = {};
            bpf_probe_read_user(&addr, sizeof(addr), ctx->upeer_sockaddr);
            args.port = bpf_ntohs(addr.sin6_port);
            bpf_probe_read_user(&args.ipv6, sizeof(args.ipv6), &addr.sin6_addr);
        }
    }

    bpf_map_update_elem(&active_accepts, &id, &args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct args_accept *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t args = {};

    if (ctx->upeer_sockaddr) {
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), ctx->upeer_sockaddr);
        args.sa_family = family;

        if (family == 2) {  // AF_INET
            struct sockaddr_in addr = {};
            bpf_probe_read_user(&addr, sizeof(addr), ctx->upeer_sockaddr);
            args.ipv4 = bpf_ntohl(addr.sin_addr.s_addr);
            args.port = bpf_ntohs(addr.sin_port);
        } else if (family == 10) {  // AF_INET6
            struct sockaddr_in6 addr = {};
            bpf_probe_read_user(&addr, sizeof(addr), ctx->upeer_sockaddr);
            args.port = bpf_ntohs(addr.sin6_port);
            bpf_probe_read_user(&args.ipv6, sizeof(args.ipv6), &addr.sin6_addr);
        }
    }

    bpf_map_update_elem(&active_accepts, &id, &args, BPF_ANY);
    return 0;
}

static __always_inline int process_exit_accept(struct args_exit *ctx, const char* syscall_name, size_t sys_len) {
    u64 id = bpf_get_current_pid_tgid();
    struct accept_args_t *args = bpf_map_lookup_elem(&active_accepts, &id);

    if (!args || ctx->ret < 0) {
        bpf_map_delete_elem(&active_accepts, &id);
        return 0;
    }

    struct so_event *event = init_event();
    if (!event) {
        bpf_map_delete_elem(&active_accepts, &id);
        return 0;
    }

    event->event_type = EV_NET;
    __builtin_memcpy(event->syscall, syscall_name, sys_len);
    event->ret = ctx->ret;
    // New File Descriptor
    event->fd = ctx->ret;

    // Use copied sockaddr data
    event->sa_family = args->sa_family;

    struct socket_data_t sock_data = {};
    sock_data.sa_family = args->sa_family;

    if (args->sa_family == 2) { // AF_INET
        event->src_ip = args->ipv4;
        event->src_port = args->port;

        sock_data.dest_ip = args->ipv4;
        sock_data.dest_port = args->port;
    } else if (args->sa_family == 10) { // AF_INET6
        event->src_port = args->port;
        __builtin_memcpy(event->src_ipv6, args->ipv6, sizeof(event->src_ipv6));

        sock_data.dest_port = args->port;
        __builtin_memcpy(sock_data.dest_ipv6, args->ipv6, sizeof(sock_data.dest_ipv6));
    }

    // Update socket_map with the NEW FD (ctx->ret) so future I/O is correlated
    u64 sock_key = (id & 0xFFFFFFFF00000000ULL) | (u32)ctx->ret;
    bpf_map_update_elem(&socket_map, &sock_key, &sock_data, BPF_ANY);

    submit(ctx, event);
    bpf_map_delete_elem(&active_accepts, &id);
    return 0;
}

SEC("tp/syscalls/sys_exit_accept")
int sys_exit_accept(struct args_exit *ctx) {
    return process_exit_accept(ctx, "accept", 7);
}

SEC("tp/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct args_exit *ctx) {
    return process_exit_accept(ctx, "accept4", 8);
}

SEC("tp/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct args_sendto *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    data.fd = ctx->fd;
    data.count = ctx->len;
    bpf_map_update_elem(&write_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_sendto")
int sys_exit_sendto(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&write_data, &id);
    if (!data) return 0;
    if (ctx->ret < 0) { bpf_map_delete_elem(&write_data, &id); return 0; }

    struct so_event *event = init_event();
    if (event) {
        event->event_type = EV_NET;
        __builtin_memcpy(event->syscall, "sendto", 7);
        event->fd = data->fd;
        event->count = data->count;
        event->bytes_rw = ctx->ret;
        event->ret = ctx->ret;

        // Try to get socket info if available
        u64 sock_key = (id & 0xFFFFFFFF00000000ULL) | (u32)event->fd;
        struct socket_data_t *sock_data = bpf_map_lookup_elem(&socket_map, &sock_key);
        if (sock_data) {
            event->dest_ip = sock_data->dest_ip;
            event->dest_port = sock_data->dest_port;
            event->sa_family = sock_data->sa_family;
        }

        submit(ctx, event);
    }
    bpf_map_delete_elem(&write_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct args_recvfrom *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    data.fd = ctx->fd;
    data.count = ctx->size;
    bpf_map_update_elem(&read_data, &id, &data, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct args_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct enter_data_t *data = bpf_map_lookup_elem(&read_data, &id);
    if (!data) return 0;
    if (ctx->ret < 4) { bpf_map_delete_elem(&read_data, &id); return 0; }

    struct so_event *event = init_event();
    if (event) {
        event->event_type = EV_NET;
        __builtin_memcpy(event->syscall, "recvfrom", 9);
        event->fd = data->fd;
        event->count = data->count;
        event->bytes_rw = ctx->ret;
        event->ret = ctx->ret;

        // Try to get socket info if available
        u64 sock_key = (id & 0xFFFFFFFF00000000ULL) | (u32)event->fd;
        struct socket_data_t *sock_data = bpf_map_lookup_elem(&socket_map, &sock_key);
        if (sock_data) {
            event->src_ip = sock_data->src_ip;
            event->src_port = sock_data->src_port;
            event->sa_family = sock_data->sa_family;
        }

        submit(ctx, event);
    }
    bpf_map_delete_elem(&read_data, &id);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone")
int sys_enter_clone(void *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    event->event_type = EV_PROC;
    __builtin_memcpy(event->syscall, "clone", 6);
    submit(ctx, event);
    return 0;
}

SEC("tp/syscalls/sys_enter_clone3")
int sys_enter_clone3(void *ctx) {
    struct so_event *event = init_event();
    if (!event) return 0;
    event->event_type = EV_PROC;
    __builtin_memcpy(event->syscall, "clone3", 7);
    submit(ctx, event);
    return 0;
}