# Copyright 2020 Kinvolk GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

def filter_by_containers(bpf_text, args):
    containers_filter_header = """
    #ifdef CGROUP_ID_SET
        BPF_TABLE_PINNED("hash", u64, u64, cgroupset, 1024, "CGROUP_PATH");
    #endif

    #ifdef MOUNT_NS_SET
        #include <linux/nsproxy.h>
        #include <linux/mount.h>
        #include <linux/ns_common.h>
        /* see mountsnoop.py:
        * XXX: struct mnt_namespace is defined in fs/mount.h, which is private
        * to the VFS and not installed in any kernel-devel packages. So, let's
        * duplicate the important part of the definition. There are actually
        * more members in the real struct, but we don't need them, and they're
        * more likely to change.
        */
        struct mnt_namespace {
            atomic_t count;
            struct ns_common ns;
        };

        BPF_TABLE_PINNED("hash", u64, u32, mount_ns_set, 1024,
            "MOUNT_NS_PATH");
    #endif
    """

    container_filters_impl = """
    #ifdef CGROUP_ID_SET
        u64 cgroupid = bpf_get_current_cgroup_id();
        if (cgroupset.lookup(&cgroupid) == NULL) {
        return 0;
        }
    #endif

    #ifdef MOUNT_NS_SET
        struct task_struct *current_task;
        current_task = (struct task_struct *)bpf_get_current_task();
        u64 ns_id = current_task->nsproxy->mnt_ns->ns.inum;
        if (mount_ns_set.lookup(&ns_id) == NULL) {
        return 0;
        }
    #endif
    """

    bpf_text = bpf_text.replace('CONTAINERS_FILTER_HEADER',
        containers_filter_header)
    bpf_text = bpf_text.replace('CONTAINERS_FILTER_IMPL',
        container_filters_impl)

    if args.cgroupmap:
        bpf_text = '#define CGROUP_ID_SET\n' + bpf_text
        bpf_text = bpf_text.replace('CGROUP_PATH', args.cgroupmap)

    if args.mntnsmap:
        bpf_text = '#define MOUNT_NS_SET\n' + bpf_text
        bpf_text = bpf_text.replace('MOUNT_NS_PATH', args.mntnsmap)

    return bpf_text
