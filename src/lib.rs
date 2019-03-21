pub use libc::*;
use nix::Error;

use std::mem;
use std::ptr;

// bunch of consts that seem to be missing from libc
pub const KERN_ALLOWKMEM: c_int = 54;
pub const KERN_WITNESS: c_int = 60;
pub const KERN_WITNESS_WATCH: c_int = 1;
pub const KERN_WXABORT: c_int = 74;

pub const DBCTL_RADIX: c_int = 1;
pub const DBCTL_MAXWIDTH: c_int = 2;
pub const DBCTL_MAXLINE: c_int = 3;
pub const DBCTL_TABSTOP: c_int = 4;
pub const DBCTL_PANIC: c_int = 5;
pub const DBCTL_CONSOLE: c_int = 6;
pub const DBCTL_LOG: c_int = 7;
pub const DBCTL_TRIGGER: c_int = 8;
pub const DBCTL_PROFILE: c_int = 9;
pub const DBCTL_MAXID: c_int = 10;

pub const FFS_CLUSTERREAD: c_int = 1;
pub const FFS_CLUSTERWRITE: c_int = 2;
pub const FFS_REALLOCBLKS: c_int = 3;
pub const FFS_ASYNCFREE: c_int = 4;
pub const FFS_MAX_SOFTDEPS: c_int = 5;
pub const FFS_SD_TICKDELAY: c_int = 6;
pub const FFS_SD_WORKLIST_PUSH: c_int = 7;
pub const FFS_SD_BLK_LIMIT_PUSH: c_int = 8;
pub const FFS_SD_INO_LIMIT_PUSH: c_int = 9;
pub const FFS_SD_BLK_LIMIT_HIT: c_int = 10;
pub const FFS_SD_INO_LIMIT_HIT: c_int = 11;
pub const FFS_SD_SYNC_LIMIT_HIT: c_int = 12;
pub const FFS_SD_INDIR_BLK_PTRS: c_int = 13;
pub const FFS_SD_INODE_BITMAP: c_int = 14;
pub const FFS_SD_DIRECT_BLK_PTRS: c_int = 15;
pub const FFS_SD_DIR_ENTRY: c_int = 16;
pub const FFS_DIRHASH_DIRSIZE: c_int = 17;
pub const FFS_DIRHASH_MAXMEM: c_int = 18;
pub const FFS_DIRHASH_MEM: c_int = 19;
pub const FFS_MAXID: c_int = 20;

pub const FS_POSIX: c_int = 1;
pub const FS_POSIX_SETUID: c_int = 1;

pub const HW_MACHINE: c_int = 1;
pub const HW_MODEL: c_int = 2;
pub const HW_NCPU: c_int = 3;
pub const HW_BYTEORDER: c_int = 4;
// TODO: deprecated by 64-bit version?
//const HW_PHYSMEM: c_int = 5;
//const HW_USERMEM: c_int = 6;
pub const HW_PAGESIZE: c_int = 7;
pub const HW_DISKNAMES: c_int = 8;
pub const HW_DISKSTATS: c_int = 9;
pub const HW_DISKCOUNT: c_int = 10;
pub const HW_SENSORS: c_int = 11;
pub const HW_CPUSPEED: c_int = 12;
pub const HW_SETPERF: c_int = 13;
pub const HW_VENDOR: c_int = 14;
pub const HW_PRODUCT: c_int = 15;
pub const HW_VERSION: c_int = 16;
pub const HW_SERIALNO: c_int = 17;
pub const HW_UUID: c_int = 18;
pub const HW_PHYSMEM64: c_int = 19;
pub const HW_USERMEM64: c_int = 20;
pub const HW_NCPUFOUND: c_int = 21;
pub const HW_ALLOWPOWERDOWN: c_int = 22;
pub const HW_PERFPOLICY: c_int = 23;
pub const HW_SMT: c_int = 24;
pub const HW_NCPUONLINE: c_int = 25;
pub const HW_MAXID: c_int = 26;

pub const CTL_DEBUG_NAME: c_int = 0;
pub const CTL_DEBUG_VALUE: c_int = 1;
pub const CTL_DEBUG_MAXID: c_int = 20;

pub type Result<T> = std::result::Result<T, Error>;

pub trait SysctlValue {

}

pub fn sysctl<S: SysctlValue>(name: &mut str, mut newp: Option<S>) -> Result<Option<S>> {
    // Management Information Base-style name
    let mib = parse_mib_str(name)?;
    let snewp: *mut _ = match &mut newp {
        Some(snewp) => snewp,
        None => ptr::null_mut(),
    };
    let mut buf = vec![0 as c_int; CTL_MAXNAME as usize];

    let mib_len = mib.len();
    let newp_len = CTL_MAXNAME as usize * mem::size_of::<*mut c_void>();
    unsafe {
        libc::sysctl(mib.as_ptr(),
                     mib_len as u32,
                     buf.as_mut_ptr() as *mut c_void,
                     &mut buf.len(),
                     snewp as *mut c_void,
                     newp_len);
    }

    unimplemented!()
}

#[cfg(target_os = "openbsd")]
pub(crate) fn parse_mib_str(name: &str) -> Result<Vec<c_int>> {
    let args: Vec<String> = name
        .split(|c| c == '=' || c == '.')
        .map(|s| format!("{}{}", s, '\0'))
        .collect();

    let mib = get_mib(&args)?;
    Ok(mib)
}

fn get_mib(names: &Vec<String>) -> Result<Vec<c_int>> {
    // allocate a buffer to hold the parsed MIB information
    let mut mib_buf = vec![0 as c_int];

    match names[0].as_str() {
        "kern" => {
            mib_buf[0] = CTL_KERN;
            mib_buf.append(&mut parse_mib_kern(&names[1..])?);
        },
        "vm" => {
            mib_buf[0] = CTL_VM;
            mib_buf.append(&mut parse_mib_vm(&names[1..])?);
        },
        "fs" => {
            mib_buf[0] = CTL_FS;
            mib_buf.append(&mut parse_mib_fs(&names[1..])?);
        },
        "net" => {
            mib_buf[0] = CTL_NET;
            mib_buf.append(&mut parse_mib_net(&names[1..])?);
        },
        "debug" => {
            mib_buf[0] = CTL_DEBUG;
            mib_buf.append(&mut parse_mib_debug(&names[1..])?);
        },
        "hw" => {
            mib_buf[0] = CTL_HW;
            mib_buf.append(&mut parse_mib_hw(&names[1..])?);
        },
        "machdep" => {
            mib_buf[0] = CTL_MACHDEP;
            mib_buf.append(&mut parse_mib_machdep(&names[1..])?);
        },
        "ddb" => {
            mib_buf[0] = CTL_DDB;
            mib_buf.append(&mut parse_mib_ddb(&names[1..])?);
        },
        "vfs" => {
            mib_buf[0] = CTL_VFS;
            mib_buf.append(&mut parse_mib_vfs(&names[1..])?);
        },
        _ => return Err(Error::invalid_argument()),
    };

    mib_buf.shrink_to_fit();
    Ok(mib_buf)
}

// 
fn parse_mib_kern(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();
    match names[0].as_str() {
        "ostype" => mib.push(KERN_OSTYPE),
        "osrelease" => mib.push(KERN_OSRELEASE),
        "osrevision" => mib.push(KERN_OSREV),
        "version" => mib.push(KERN_VERSION),
        "maxvnodes" => mib.push(KERN_MAXVNODES),
        "maxproc" => mib.push(KERN_MAXPROC),
        "maxfiles" => mib.push(KERN_MAXFILES),
        "argmax" => mib.push(KERN_ARGMAX),
        "securelevel" => mib.push(KERN_SECURELVL),
        "hostname" => mib.push(KERN_HOSTNAME),
        "hostid" => mib.push(KERN_HOSTID),
        "clockrate" => mib.push(KERN_CLOCKRATE),
        "profiling" => mib.push(KERN_PROF),
        "posix1version" => mib.push(KERN_POSIX1),
        "ngroups" => mib.push(KERN_NGROUPS),
        "job_control" => mib.push(KERN_JOB_CONTROL),
        "saved_ids" => mib.push(KERN_SAVED_IDS),
        "boottime" => mib.push(KERN_BOOTTIME),
        "domainname" => mib.push(KERN_DOMAINNAME),
        "maxpartitions" => mib.push(KERN_MAXPARTITIONS),
        "rawpartition" => mib.push(KERN_RAWPARTITION),
        "maxthread" => mib.push(KERN_MAXTHREAD),
        "nthreads" => mib.push(KERN_NTHREADS),
        "osversion" => mib.push(KERN_OSVERSION),
        "somaxconn" => mib.push(KERN_SOMAXCONN),
        "sominconn" => mib.push(KERN_SOMINCONN),
        "nosuidcoredump" => mib.push(KERN_NOSUIDCOREDUMP),
        "fsync" => mib.push(KERN_FSYNC),
        "sysvmsg" => mib.push(KERN_SYSVMSG),
        "sysvsem" => mib.push(KERN_SYSVSEM),
        "sysvshm" => mib.push(KERN_SYSVSHM),
        "msgbufsize" => mib.push(KERN_MSGBUFSIZE),
        "malloc" => {
            mib.push(KERN_MALLOCSTATS);
            match names[1].as_str() {
                "bucket" => unimplemented!(),
                "buckets" => unimplemented!(),
                "kmemnames" => unimplemented!(),
                "kmemstat" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "cp_time" => mib.push(KERN_CPTIME),
        "nchstats" => {
            mib.push(KERN_NCHSTATS);
            match names[1].as_str() {
                "good_hits" => unimplemented!(),
                "negative_hits" => unimplemented!(),
                "bad_hits" => unimplemented!(),
                "false_hits" => unimplemented!(),
                "misses" => unimplemented!(),
                "long_names" => unimplemented!(),
                "pass2" => unimplemented!(),
                "2passes" => unimplemented!(),
                "ncs_revhits" => unimplemented!(),
                "ncs_revmiss" => unimplemented!(),
                "ncs_dothits" => unimplemented!(),
                "nch_dotdothits" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "forkstat" => {
            mib.push(KERN_FORKSTAT);
            match names[1].as_str() {
                "forks" => unimplemented!(),
                "vforks" => unimplemented!(),
                "tforks" => unimplemented!(),
                "kthreads" => unimplemented!(),
                "fork_pages" => unimplemented!(),
                "vfork_pages" => unimplemented!(),
                "tfork_pages" => unimplemented!(),
                "kthread_pages" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "nselcoll" => mib.push(KERN_NSELCOLL),
        "tty" => {
            mib.push(KERN_TTY);
            match names[1].as_str() {
                "tk_nin" => unimplemented!(),
                "tk_nout" => unimplemented!(),
                "tk_rawcc" => unimplemented!(),
                "tk_cancc" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "ccpu" => mib.push(KERN_CCPU),
        "fscale" => mib.push(KERN_FSCALE),
        "nprocs" => mib.push(KERN_NPROCS),
        "msgbuf" => mib.push(KERN_MSGBUF),
        "pool" => mib.push(KERN_POOL),
        "stackgap_random" => mib.push(KERN_STACKGAPRANDOM),
        "sysvipc_info" => mib.push(KERN_SYSVIPC_INFO),
        "allowkmem" => mib.push(KERN_ALLOWKMEM),
        "splassert" => mib.push(KERN_SPLASSERT),
        "procargs" => mib.push(KERN_PROC_ARGS),
        "nfiles" => mib.push(KERN_NFILES),
        "ttycount" => mib.push(KERN_TTYCOUNT),
        "numvnodes" => mib.push(KERN_NUMVNODES),
        "mbstat" => mib.push(KERN_MBSTAT),
        "witness" => mib.push(KERN_WITNESS),
        "seminfo" => {
            mib.push(KERN_SEMINFO);
            match names[1].as_str() {
                "semmni" => unimplemented!(),
                "semmns" => unimplemented!(),
                "semmsl" => unimplemented!(),
                "semopm" => unimplemented!(),
                "semume" => unimplemented!(),
                "semusz" => unimplemented!(),
                "semvmx" => unimplemented!(),
                "semaem" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "shminfo" => {
            mib.push(KERN_SHMINFO);
            match names[1].as_str() {
                "shmmax" => unimplemented!(),
                "shmmin" => unimplemented!(),
                "shmmni" => unimplemented!(),
                "shmseg" => unimplemented!(),
                "shmall" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "intrcnt" => mib.push(KERN_INTRCNT),
        "watchdog" => {
            mib.push(KERN_WATCHDOG);
            match names[1].as_str() {
                "period" => unimplemented!(),
                "auto" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "proc" => {
            mib.push(KERN_PROC);
            match names[1].as_str() {
                "" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "maxclusters" => mib.push(KERN_MAXCLUSTERS),
        // TODO
        "evcount" => mib.push(KERN_EVCOUNT),
        "timecounter" => {
            mib.push(KERN_TIMECOUNTER);
            match names[1].as_str() {
                "tick" => unimplemented!(),
                "timestepwarnings" => unimplemented!(),
                "hardware" => unimplemented!(),
                "choice" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "maxlocksperuid" => mib.push(KERN_MAXLOCKSPERUID),
        // TODO
        "cp_time2" => mib.push(KERN_CPTIME2),
        "bufcachepercent" => mib.push(KERN_CACHEPCT),
        "file" => mib.push(KERN_FILE),
        "wxabort" => mib.push(KERN_WXABORT),
        "consdev" => mib.push(KERN_CONSDEV),
        "netlivelocks" => mib.push(KERN_NETLIVELOCKS),
        "pool_debug" => mib.push(KERN_POOL_DEBUG),
        // TODO
        "pool_cwd" => mib.push(KERN_PROC_CWD),
        // TODO
        "proc_nobroadcastkill" => mib.push(KERN_PROC_NOBROADCASTKILL),
        "proc_vmmap" => mib.push(KERN_PROC_VMMAP),
        "global_ptrace" => mib.push(KERN_GLOBAL_PTRACE),
        // TODO
        "" => mib.push(KERN_CONSBUFSIZE),
        "" => mib.push(KERN_CONSBUF),
        "audio" => {
            mib.push(KERN_AUDIO);
            match names[1].as_str() {
                "record" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        _ => return Err(Error::invalid_argument()),
    };

    Ok(mib)
}

fn parse_mib_vm(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();

    match names[0].as_str() {
        _ => return Err(Error::invalid_argument()),
    }

    Ok(mib)
}

fn parse_mib_fs(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();

    match names[0].as_str() {
        "posix" => {
            mib.push(FS_POSIX);
            match names[1].as_str() {
                "setuid" => mib.push(FS_POSIX_SETUID),
                _ => return Err(Error::invalid_argument()),
            }
        },
        _ => return Err(Error::invalid_argument()),
    }

    Ok(mib)
}

fn parse_mib_net(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();

    match names[0].as_str() {
        _ => return Err(Error::invalid_argument()),
    }

    Ok(mib)
}

fn parse_mib_debug(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();

    match names[0].as_str() {
        "name" => mib.push(CTL_DEBUG_NAME),
        "value" => mib.push(CTL_DEBUG_VALUE),
        _ => return Err(Error::invalid_argument()),
    }

    Ok(mib)
}

fn parse_mib_hw(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();

    match names[0].as_str() {
        "machine" => mib.push(HW_MACHINE),
        "model" => mib.push(HW_MODEL),
        "ncpu" => mib.push(HW_NCPU),
        "byteorder" => mib.push(HW_BYTEORDER),
        // TODO: deprecated by 64-bit version?
        //"physmem" => mib.push(HW_PHYSMEM),
        //"usermem" => mib.push(HW_USERMEM),
        "pagesize" => mib.push(HW_PAGESIZE),
        "disknames" => mib.push(HW_DISKNAMES),
        "diskstats" => mib.push(HW_DISKSTATS),
        "diskcount" => mib.push(HW_DISKCOUNT),
        "sensors" => mib.push(HW_SENSORS),
        "cpuspeed" => mib.push(HW_CPUSPEED),
        "setperf" => mib.push(HW_SETPERF),
        "vendor" => mib.push(HW_VENDOR),
        "product" => mib.push(HW_PRODUCT),
        "version" => mib.push(HW_VERSION),
        "serialno" => mib.push(HW_SERIALNO),
        "uuid" => mib.push(HW_UUID),
        "physmem" => mib.push(HW_PHYSMEM64),
        "usermem" => mib.push(HW_USERMEM64),
        "npcufound" => mib.push(HW_NCPUFOUND),
        "allowpowerdown" => mib.push(HW_ALLOWPOWERDOWN),
        "perfpolicy" => mib.push(HW_PERFPOLICY),
        "smt" => mib.push(HW_SMT),
        "ncpuonline" => mib.push(HW_NCPUONLINE),
        _ => return Err(Error::invalid_argument()),
    };

    Ok(mib)
}

fn parse_mib_machdep(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();

    match names[0].as_str() {
        _ => return Err(Error::invalid_argument()),
    }

    Ok(mib)
}

fn parse_mib_ddb(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();

    match names[0].as_str() {
        "radix" => mib.push(DBCTL_RADIX),
        "max_width" => mib.push(DBCTL_MAXWIDTH),
        "max_line" => mib.push(DBCTL_MAXLINE),
        "tab_stop_width" => mib.push(DBCTL_TABSTOP),
        "panic" => mib.push(DBCTL_PANIC),
        "console" => mib.push(DBCTL_CONSOLE),
        "log" => mib.push(DBCTL_LOG),
        "trigger" => mib.push(DBCTL_TRIGGER),
        "profile" => mib.push(DBCTL_PROFILE),
        _ => return Err(Error::invalid_argument()),
    }

    Ok(mib)
}

fn parse_mib_vfs(names: &[String]) -> Result<Vec<c_int>> {
    let mut mib = Vec::new();
    match names[0].as_str() {
        "generic" => unimplemented!(),
        "conf" => unimplemented!(),
        "ffs" => {
            mib.push(FFS);
            match names[1].as_str() {
                "" => mib.push(FFS_CLUSTERREAD),
                "" => mib.push(FFS_CLUSTERWRITE),
                "" => mib.push(FFS_REALLOCBLKS),
                "" => mib.push(FFS_ASYNCFREE),
                "max_softdeps" => mib.push(FFS_MAX_SOFTDEPS),
                "sd_tickdelay" => mib.push(FFS_SD_TICKDELAY),
                "sd_worklist_push" => mib.push(FFS_SD_WORKLIST_PUSH),
                "sd_blk_limit_push" => mib.push(FFS_SD_BLK_LIMIT_PUSH),
                "sd_ino_limit_push" => mib.push(FFS_SD_INO_LIMIT_PUSH),
                "sd_blk_limit_hit" => mib.push(FFS_SD_BLK_LIMIT_HIT),
                "sd_ino_limit_hit" => mib.push(FFS_SD_INO_LIMIT_HIT),
                "sd_sync_limit_hit" => mib.push(FFS_SD_SYNC_LIMIT_HIT),
                "sd_indir_blk_ptrs" => mib.push(FFS_SD_INDIR_BLK_PTRS),
                "sd_inode_bitmap" => mib.push(FFS_SD_INODE_BITMAP),
                "sd_direct_blk_ptrs" => mib.push(FFS_SD_DIRECT_BLK_PTRS),
                "sd_dir_entry" => mib.push(FFS_SD_DIR_ENTRY),
                "dirhash_dirsize" => mib.push(FFS_DIRHASH_DIRSIZE),
                "dirhash_maxmem" => mib.push(FFS_DIRHASH_MAXMEM),
                "dirhash_mem" => mib.push(FFS_DIRHASH_MEM),
                _ => return Err(Error::invalid_argument()),
            }
        }
    };

    Ok(mib)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
