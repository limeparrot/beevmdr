#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_BUF_DIM 32768
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_BUF_DIM);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, u32);
  __type(value, struct strbuf);
} stringbuf SEC(".maps");

#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))
#define MAX_STRING_SIZE 2048
#define MAX_PATH_SIZE 2048
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 20

struct strbuf {
  u_char data[MAX_PERCPU_ARRAY_SIZE];
};

static __always_inline long filename_from_path(u_char **filename,
                                               const struct path *path) {
  u32 idx = 0;
  struct strbuf *buf = bpf_map_lookup_elem(&stringbuf, &idx);
  if (buf == NULL) {
    return 0;
  }
  struct dentry *dentry, *dentry_parent, *dentry_mnt;
  struct vfsmount *vfsmnt;
  struct mount *mnt, *mnt_parent;
  const u_char *name;
  size_t name_len;
  long ret;
  dentry = BPF_CORE_READ(path, dentry);
  vfsmnt = BPF_CORE_READ(path, mnt);
  mnt = container_of(vfsmnt, struct mount, mnt);
  mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
  size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

#pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
    dentry_parent = BPF_CORE_READ(dentry, d_parent);
    if (dentry == dentry_mnt || dentry == dentry_parent) {
      if (dentry != dentry_mnt) {
        break;
      }
      if (mnt != mnt_parent) {
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
        vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
        continue;
      }
      break;
    }
    name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len));
    name = BPF_CORE_READ(dentry, d_name.name);
    name_len = name_len + 1;
    if (name_len > buf_off) {
      break;
    }
    volatile size_t new_buff_offset = buf_off - name_len;
    ret = bpf_probe_read_kernel_str(
        &(buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buff_offset)]), name_len,
        name);
    if (ret < 0) {
      return ret;
    }
    if (ret > 1) {
      buf_off -= 1;
      buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
      buf->data[buf_off] = '/';
      buf_off -= ret - 1;
      buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
    } else {
      break;
    }
    dentry = dentry_parent;
  }

  if (buf_off != 0) {
    buf_off -= 1;
    buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off);
    buf->data[buf_off] = '/';
  }
  buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
  *filename = &buf->data[buf_off];
  return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid;
  __u32 tgid = pid_tgid >> 32;
  __u64 timestamp = bpf_ktime_get_ns();
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct file *file = BPF_CORE_READ(task, mm, exe_file);
  struct path *path = __builtin_preserve_access_index(&file->f_path);
    u_char *dir = NULL;
	long ret = filename_from_path(&dir, path);
	if (ret < 0)
		return 0;
    bpf_printk("%s: %s",comm, dir);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";