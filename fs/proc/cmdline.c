// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int cmdline_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", saved_command_line);
	return 0;
}

static int cmdline_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, cmdline_proc_show, NULL);
}

static const struct file_operations cmdline_proc_fops = {
	.open		= cmdline_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/**
    Set all known SafetyNet flags to fake a full locked and
    verified device. SafetyNet checks more then just that,
    especially work-around key attestation:
    https://github.com/kdrag0n/safetynet-fix
**/
static void remove_flag(char *cmd, const char *flag)
{
        char *start_addr, *end_addr;

        /* Ensure all instances of a flag are removed */
        while ((start_addr = strstr(cmd, flag))) {
                end_addr = strchr(start_addr, ' ');
                if (end_addr)
                        memmove(start_addr, end_addr + 1, strlen(end_addr));
                else
                        *(start_addr - 1) = '\0';
        }
}

static void remove_safetynet_flags(char *cmd)
{
        remove_flag(cmd, "androidboot.enable_dm_verity=");
        remove_flag(cmd, "androidboot.secboot=");
        remove_flag(cmd, "androidboot.veritymode=");
        remove_flag(cmd, "bootlock=");
        remove_flag(cmd, "androidboot.vbmeta.device_state");
        remove_flag(cmd, "androidboot.verifiedbootstate=");
}

static void set_safetynet_flags(char *cmd)
{
	char sflags[400] = " androidboot.enable_dm_verity=1 androidboot.secboot=enabled androidboot.veritymode=enforcing androidboot.vbmeta.device_state=locked androidboot.verifiedbootstate=green";
	memcpy(cmd, strcat(cmd,sflags), sizeof(sflags) + sizeof(cmd));
}

static int __init proc_cmdline_init(void)
{
	remove_safetynet_flags(saved_command_line);
	set_safetynet_flags(saved_command_line);
	proc_create("cmdline", 0, NULL, &cmdline_proc_fops);

	return 0;
}
fs_initcall(proc_cmdline_init);
