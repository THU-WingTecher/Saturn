#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>

#define MAX_PATH_DEPTH 8
#define MAX_PATH 32
#define MAX_FILEPATH_LENGTH (MAX_PATH_DEPTH * MAX_PATH)
typedef struct
{
	char payload[MAX_FILEPATH_LENGTH];
} payload_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * refer to tools/testing/selftests/bpf/progs/profiler.inc.h
 * filename output format: 001/001/usb/bus/
 */
static inline int read_absolute_file_path_from_dentry(struct dentry *filp_dentry, char *payload)
{
	size_t length = 0;
	size_t filepart_length;
	struct dentry *parent_dentry;

#pragma unroll
	for (int i = 0; i < MAX_PATH_DEPTH; i++)
	{
		filepart_length = bpf_probe_read_kernel_str(payload, MAX_PATH,
													BPF_CORE_READ(filp_dentry, d_name.name));

		barrier_var(filepart_length);
		if (filepart_length > MAX_PATH)
			break;
		barrier_var(filepart_length);

		parent_dentry = BPF_CORE_READ(filp_dentry, d_parent);
		if (filp_dentry == parent_dentry)
		{
			*payload = '\0';
			break;
		}
		filp_dentry = parent_dentry;

		payload += (filepart_length - 1);
		*payload = '/';
		payload++;
		length += filepart_length;
	}

	return length;
}

SEC("kretprobe/do_filp_open")
int BPF_KRETPROBE(do_filp_open_exit, long ret)
{
	struct file *filp = (void *)ret;
	struct dentry *dentry;

	if (!filp)
		return 0;
	dentry = BPF_CORE_READ(filp, f_path.dentry);
	if (!dentry)
		return 0;
	const char *filename = BPF_CORE_READ(dentry, d_name.name);

	struct file_operations *f_ops = BPF_CORE_READ(filp, f_op);

	payload_t payloadd;
	memset(payloadd.payload, 0, MAX_FILEPATH_LENGTH);

	char *payload_ptr = &(payloadd.payload);
	int len = read_absolute_file_path_from_dentry(dentry, payload_ptr);

	bpf_printk("KPROBE EXIT: filename = %s, full path = %s, addr = %p, addr name = %ps", filename, payload_ptr, f_ops, f_ops);
	return 0;
}
