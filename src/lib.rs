//! Hopefully some helpful functions and other stuff for making
//! [`sysctl(2)`](https://man.openbsd.org/sysctl.2) calls on OpenBSD.
//!
//!```text
//!       _____
//!     \-     -/        ________
//!  \_/         \      /        \
//!  |       O  O |    <  sysctl! )
//!  |_   <   ) 3 )     \________/
//!  / \         /
//!     /-_____-\
//!```
//!
//! Calling `sysctl` can be scary, dear reader. There's `unsafe` and `void*`,
//! and that means letting go of type safety and borrow checking, two of our
//! best Rust friends! Fortunately we can use macros and careful manual type
//! checking to provide better guarantees to ourselves and expose a way to make
//! relatively safe `sysctl` calls.
#![allow(dead_code, unused_variables)]
pub use libc;
use libc::*;
use nix::Error;

use std::any::Any;
use std::mem;
use std::ptr;

// bunch of consts that seem to be missing from libc
const KERN_ALLOWKMEM: c_int = 54;
const KERN_AUDIO_RECORD: c_int = 1;
const KERN_MALLOC_BUCKET: c_int = 2;
const KERN_MALLOC_BUCKETS: c_int = 1;
const KERN_MALLOC_KMEMNAMES: c_int = 3;
const KERN_MALLOC_KMEMSTAT: c_int = 4;
const KERN_SEMINFO_SEMAEM: c_int = 9;
const KERN_SEMINFO_SEMMNI: c_int = 1;
const KERN_SEMINFO_SEMMNS: c_int = 2;
const KERN_SEMINFO_SEMMNU: c_int = 3;
const KERN_SEMINFO_SEMMSL: c_int = 4;
const KERN_SEMINFO_SEMOPM: c_int = 5;
const KERN_SEMINFO_SEMUME: c_int = 6;
const KERN_SEMINFO_SEMUSZ: c_int = 7;
const KERN_SEMINFO_SEMVMX: c_int = 8;
const KERN_SHMINFO_SHMALL: c_int = 5;
const KERN_SHMINFO_SHMMAX: c_int = 1;
const KERN_SHMINFO_SHMMIN: c_int = 2;
const KERN_SHMINFO_SHMMNI: c_int = 3;
const KERN_SHMINFO_SHMSEG: c_int = 4;
const KERN_TIMECOUNTER_CHOICE: c_int = 4;
const KERN_TIMECOUNTER_HARDWARE: c_int = 3;
const KERN_TIMECOUNTER_TICK: c_int = 1;
const KERN_TIMECOUNTER_TIMESTEPWARNINGS: c_int = 2;
const KERN_WATCHDOG_AUTO: c_int = 2;
const KERN_WATCHDOG_PERIOD: c_int = 1;
const KERN_WITNESS: c_int = 60;
const KERN_WITNESS_WATCH: c_int = 1;
const KERN_WXABORT: c_int = 74;

const DBCTL_RADIX: c_int = 1;
const DBCTL_MAXWIDTH: c_int = 2;
const DBCTL_MAXLINE: c_int = 3;
const DBCTL_TABSTOP: c_int = 4;
const DBCTL_PANIC: c_int = 5;
const DBCTL_CONSOLE: c_int = 6;
const DBCTL_LOG: c_int = 7;
const DBCTL_TRIGGER: c_int = 8;
const DBCTL_PROFILE: c_int = 9;
const DBCTL_MAXID: c_int = 10;

// vfs
const FFS_CLUSTERREAD: c_int = 1;
const FFS_CLUSTERWRITE: c_int = 2;
const FFS_REALLOCBLKS: c_int = 3;
const FFS_ASYNCFREE: c_int = 4;
const FFS_MAX_SOFTDEPS: c_int = 5;
const FFS_SD_TICKDELAY: c_int = 6;
const FFS_SD_WORKLIST_PUSH: c_int = 7;
const FFS_SD_BLK_LIMIT_PUSH: c_int = 8;
const FFS_SD_INO_LIMIT_PUSH: c_int = 9;
const FFS_SD_BLK_LIMIT_HIT: c_int = 10;
const FFS_SD_INO_LIMIT_HIT: c_int = 11;
const FFS_SD_SYNC_LIMIT_HIT: c_int = 12;
const FFS_SD_INDIR_BLK_PTRS: c_int = 13;
const FFS_SD_INODE_BITMAP: c_int = 14;
const FFS_SD_DIRECT_BLK_PTRS: c_int = 15;
const FFS_SD_DIR_ENTRY: c_int = 16;
const FFS_DIRHASH_DIRSIZE: c_int = 17;
const FFS_DIRHASH_MAXMEM: c_int = 18;
const FFS_DIRHASH_MEM: c_int = 19;
const FFS_MAXID: c_int = 20;

const FUSEFS_INBUFS: c_int = 2;
const FUSEFS_OPENDEVS: c_int = 1;
const FUSEFS_POOL_NBPAGES: c_int = 4;
const FUSEFS_WAITBUFS: c_int = 3;

const FS_POSIX: c_int = 1;
const FS_POSIX_SETUID: c_int = 1;

// hw
const HW_MACHINE: c_int = 1;
const HW_MODEL: c_int = 2;
const HW_NCPU: c_int = 3;
const HW_BYTEORDER: c_int = 4;
// TODO: deprecated by 64-bit version?
//const HW_PHYSMEM: c_int = 5;
//const HW_USERMEM: c_int = 6;
const HW_PAGESIZE: c_int = 7;
const HW_DISKNAMES: c_int = 8;
const HW_DISKSTATS: c_int = 9;
const HW_DISKCOUNT: c_int = 10;
const HW_SENSORS: c_int = 11;
const HW_CPUSPEED: c_int = 12;
const HW_SETPERF: c_int = 13;
const HW_VENDOR: c_int = 14;
const HW_PRODUCT: c_int = 15;
const HW_VERSION: c_int = 16;
const HW_SERIALNO: c_int = 17;
const HW_UUID: c_int = 18;
const HW_PHYSMEM64: c_int = 19;
const HW_USERMEM64: c_int = 20;
const HW_NCPUFOUND: c_int = 21;
const HW_ALLOWPOWERDOWN: c_int = 22;
const HW_PERFPOLICY: c_int = 23;
const HW_SMT: c_int = 24;
const HW_NCPUONLINE: c_int = 25;
const HW_MAXID: c_int = 26;

const MACHDEP_ALLOWAPERTURE: c_int = 5;
const MACHDEP_KBDRESET: c_int = 10;
const MACHDEP_LIDACTION: c_int = 14;
const MACHDEP_PWRACTION: c_int = 18;

const MPLSCTL_DEFTTL: c_int = 2;
const MPLSCTL_MAPTTL_IP: c_int = 5;
const MPLSCTL_MAPTTL_IP6: c_int = 6;
const MPLSCTL_MAXINKLOOP: c_int = 4;

const NFS_NFSSTATS: c_int = 1;
const NFS_NIOTHREADS: c_int = 2;

const PIPEXCTL_ENABLE: c_int = 1;
const PIPEXCTL_INQ: c_int = 2;
const PIPEXCTL_OUTQ: c_int = 3;

const VM_ANONMIN: c_int = 7;
const VM_LOADAVG: c_int = 2;
const VM_MALLOC_CONF: c_int = 12;
const VM_MAXSLP: c_int = 10;
const VM_METER: c_int = 1;
const VM_NKMEMPAGES: c_int = 6;
const VM_PSSTRINGS: c_int = 3;
const VM_SWAPENCRYPT: c_int = 5;
const VM_USPACE: c_int = 11;
const VM_UVMEXP: c_int = 4;
const VM_VNODEMIN: c_int = 9;
const VM_VTEXTMIN: c_int = 8;

// net
const AF_INET: c_int = 2;
const AF_INET6: c_int = 24;
const PF_INET: c_int = AF_INET;
const PF_INET6: c_int = AF_INET6;

const CTL_DEBUG_NAME: c_int = 0;
const CTL_DEBUG_VALUE: c_int = 1;
const CTL_DEBUG_MAXID: c_int = 20;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
enum SysctlType {
    DevT,
    Int64,
    Int32,
    Long,
    Node,
    SysString,
    SysStruct,
    UInt8Slice,
    UInt32Slice,
    UInt64Slice,
    UShortSlice,
}

#[derive(Clone, Debug, PartialEq)]
struct Sysctl {
    mib: Vec<c_int>,
    value_type: SysctlType,
    changeable: bool,
}

/// ```
/// let mut buf = vec![0u8; libc::CTL_MAXNAME as usize];
/// ```
#[macro_export]
macro_rules! sysctl_read {
    ($fn_name:ident, $sysctl_name:expr, $ty:ty) => {
        pub unsafe fn $fn_name(oldp: &mut $ty) -> $crate::Result<()> {
            $crate::sysctl_raw($sysctl_name,
                               oldp.as_mut_ptr() as *mut $crate::libc::c_void,
                               std::ptr::null_mut())?;
            Ok(())
        }
    };
}

#[macro_export]
macro_rules! sysctl_write {
    ($fn_name:ident, $sysctl_name:expr, $ty:ty) => {
        pub unsafe fn $fn_name(oldp: &mut $ty, newp: &mut $ty) -> $crate::Result<()> {
            $crate::sysctl_raw($sysctl_name,
                               std::ptr::null_mut(),
                               oldp.as_mut_ptr() as *mut $crate::libc::c_void)?;
            Ok(())
        }
    };
}

#[macro_export]
macro_rules! sysctl_readwrite {
    ($fn_name:ident, $sysctl_name:expr, $ty:ty) => {
        pub unsafe fn $fn_name(oldp: &mut $ty, newp: &mut $ty) -> $crate::Result<()> {
            $crate::sysctl_raw($sysctl_name,
                               oldp.as_mut_ptr() as *mut $crate::libc::c_void,
                               newp.as_mut_ptr() as *mut $crate::libc::c_void)?;
            Ok(())
        }
    };
}

pub fn sysctl_raw(name: &str, oldp: *mut c_void, newp: *mut c_void) -> Result<()> {
    // Management Information Base-style name
    let sysctl_s = parse_mib_str(name)?;

    let mut len = mem::size_of::<*mut c_void>();
    let mib_len = sysctl_s.mib.len();
    let newp_len = CTL_MAXNAME as usize * mem::size_of::<*mut c_void>();

    // if we're getting a string we have to get the length from sysctl before
    // actually passing in the buffer we want the string written to and 
    // allocate space for the buffer based on that
    if sysctl_s.value_type == SysctlType::SysString {
        let res = unsafe {
            libc::sysctl(sysctl_s.mib.as_ptr(),
                         mib_len as u32,
                         ptr::null_mut() as *mut c_void,
                         &mut len,
                         ptr::null_mut() as *mut c_void,
                         0)
        };

        if res < 0 {
            let e = nix::errno::errno();
            return Err(Error::Sys(nix::errno::from_i32(e)));
        }
    }

    let res = unsafe {
        libc::sysctl(sysctl_s.mib.as_ptr(),
                     mib_len as u32,
                     oldp,
                     &mut len,
                     newp,
                     newp_len)
    };

    if res < 0 {
        let e = nix::errno::errno();
        Err(Error::Sys(nix::errno::from_i32(e)))
    } else {
        Ok(())
    }
}

fn parse_mib_str(name: &str) -> Result<Sysctl> {
    let args: Vec<String> = name
        .split(|c| c == '=' || c == '.')
        .map(|s| format!("{}", s))
        .collect();

    let res = get_sysctl(&args)?;

    Ok(res)
}

fn get_sysctl(names: &Vec<String>) -> Result<Sysctl> {
    match names[0].as_str() {
        "kern" => parse_mib_kern(&names[1..]),
        "vm" => parse_mib_vm(&names[1..]),
        "fs" => parse_mib_fs(&names[1..]),
        "net" => parse_mib_net(&names[1..]),
        "debug" => parse_mib_debug(&names[1..]),
        "hw" => parse_mib_hw(&names[1..]),
        "machdep" => parse_mib_machdep(&names[1..]),
        "ddb" => parse_mib_ddb(&names[1..]),
        "vfs" => parse_mib_vfs(&names[1..]),
        _ => Err(Error::invalid_argument()),
    }
}

fn parse_mib_kern(names: &[String]) -> Result<Sysctl> {
    // allocate a buffer to hold the parsed MIB information
    let mut mib = vec![CTL_KERN as c_int];
    let mut value_type = SysctlType::Int32;
    let mut changeable = false;

    match names[0].as_str() {
        "ostype" => {
            mib.push(KERN_OSTYPE);
            value_type = SysctlType::SysString
        },
        "osrelease" => {
            mib.push(KERN_OSRELEASE);
            value_type = SysctlType::SysString;
        },
        "osrevision" => mib.push(KERN_OSREV),
        "version" => {
            mib.push(KERN_VERSION);
            value_type = SysctlType::SysString;
        },
        "maxvnodes" => {
            mib.push(KERN_MAXVNODES);
            changeable = true;
        },
        "maxproc" => {
            mib.push(KERN_MAXPROC);
            changeable = true;
        },
        "maxfiles" => {
            mib.push(KERN_MAXFILES);
            changeable = true;
        },
        "argmax" => mib.push(KERN_ARGMAX),
        "securelevel" => {
            mib.push(KERN_SECURELVL);
            changeable = true;
        },
        "hostname" => {
            mib.push(KERN_HOSTNAME);
            value_type = SysctlType::SysString;
            changeable = true;
        },
        "hostid" => {
            mib.push(KERN_HOSTID);
            changeable = true;
        },
        "clockrate" => {
            mib.push(KERN_CLOCKRATE);
            value_type = SysctlType::SysStruct;
        },
        "profiling" => {
            mib.push(KERN_PROF);
            value_type = SysctlType::Node;
        },
        "posix1version" => mib.push(KERN_POSIX1),
        "ngroups" => mib.push(KERN_NGROUPS),
        "job_control" => mib.push(KERN_JOB_CONTROL),
        "saved_ids" => mib.push(KERN_SAVED_IDS),
        "boottime" => {
            mib.push(KERN_BOOTTIME);
            value_type = SysctlType::SysStruct;
        },
        "domainname" => {
            mib.push(KERN_DOMAINNAME);
            value_type = SysctlType::SysString;
            changeable = true;
        },
        "maxpartitions" => mib.push(KERN_MAXPARTITIONS),
        "rawpartition" => mib.push(KERN_RAWPARTITION),
        "maxthread" => {
            mib.push(KERN_MAXTHREAD);
            changeable = true;
        },
        "nthreads" => mib.push(KERN_NTHREADS),
        "osversion" => {
            mib.push(KERN_OSVERSION);
            value_type = SysctlType::SysString;
        },
        "somaxconn" => {
            mib.push(KERN_SOMAXCONN);
            changeable = true;
        },
        "sominconn" => {
            mib.push(KERN_SOMINCONN);
            changeable = true;
        },
        "nosuidcoredump" => {
            mib.push(KERN_NOSUIDCOREDUMP);
            changeable = true;
        },
        "fsync" => mib.push(KERN_FSYNC),
        "sysvmsg" => mib.push(KERN_SYSVMSG),
        "sysvsem" => mib.push(KERN_SYSVSEM),
        "sysvshm" => mib.push(KERN_SYSVSHM),
        "msgbufsize" => mib.push(KERN_MSGBUFSIZE),
        "malloc" => {
            mib.push(KERN_MALLOCSTATS);
            match names[1].as_str() {
                "bucket" => {
                    mib.push(KERN_MALLOC_BUCKET);
                    value_type = SysctlType::Node;
                },
                "buckets" => {
                    mib.push(KERN_MALLOC_BUCKETS);
                    value_type = SysctlType::SysString;
                },
                "kmemnames" => {
                    mib.push(KERN_MALLOC_KMEMNAMES);
                    value_type = SysctlType::SysString;
                },
                "kmemstat" => {
                    mib.push(KERN_MALLOC_KMEMSTAT);
                    value_type = SysctlType::Node;
                },
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
        "allowkmem" => {
            mib.push(KERN_ALLOWKMEM);
            changeable = true;
        },
        "splassert" => {
            mib.push(KERN_SPLASSERT);
            changeable = true;
        },
        "procargs" => {
            mib.push(KERN_PROC_ARGS);
            value_type = SysctlType::Node;
        },
        "nfiles" => mib.push(KERN_NFILES),
        "ttycount" => mib.push(KERN_TTYCOUNT),
        "numvnodes" => mib.push(KERN_NUMVNODES),
        "mbstat" => {
            mib.push(KERN_MBSTAT);
            value_type = SysctlType::SysStruct;
        },
        "witness" => {
            mib.push(KERN_WITNESS);
            value_type = SysctlType::Node;
        },
        "seminfo" => {
            mib.push(KERN_SEMINFO);
            match names[1].as_str() {
                "semmni" => {
                    mib.push(KERN_SEMINFO_SEMMNI);
                    changeable = true;
                },
                "semmns" => {
                    mib.push(KERN_SEMINFO_SEMMNS);
                    changeable = true;
                },
                "semmsl" => {
                    mib.push(KERN_SEMINFO_SEMMSL);
                    changeable = true;
                },
                "semopm" => {
                    mib.push(KERN_SEMINFO_SEMOPM);
                    changeable = true;
                },
                "semume" => mib.push(KERN_SEMINFO_SEMUME),
                "semusz" => mib.push(KERN_SEMINFO_SEMUSZ),
                "semvmx" => mib.push(KERN_SEMINFO_SEMVMX),
                "semaem" => mib.push(KERN_SEMINFO_SEMAEM),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "shminfo" => {
            mib.push(KERN_SHMINFO);
            match names[1].as_str() {
                "shmmax" => {
                    mib.push(KERN_SHMINFO_SHMMAX);
                    changeable = true
                },
                "shmmin" => {
                    mib.push(KERN_SHMINFO_SHMMIN);
                    changeable = true
                },
                "shmmni" => {
                    mib.push(KERN_SHMINFO_SHMMNI);
                    changeable = true
                },
                "shmseg" => {
                    mib.push(KERN_SHMINFO_SHMSEG);
                    changeable = true
                },
                "shmall" => {
                    mib.push(KERN_SHMINFO_SHMALL);
                    changeable = true;
                },
                _ => return Err(Error::invalid_argument()),
            }
        },
        "intrcnt" => {
            mib.push(KERN_INTRCNT);
            value_type = SysctlType::Node;
        },
        "watchdog" => {
            mib.push(KERN_WATCHDOG);
            changeable = true;
            match names[1].as_str() {
                "period" => mib.push(KERN_WATCHDOG_PERIOD),
                "auto" => mib.push(KERN_WATCHDOG_AUTO),
                _ => return Err(Error::invalid_argument()),
            }
        },
        // TODO
        "proc" => {
            mib.push(KERN_PROC);
            match names[1].as_str() {
                "" => unimplemented!(),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "maxclusters" => {
            mib.push(KERN_MAXCLUSTERS);
            changeable = true;
        },
        // TODO
        "evcount" => mib.push(KERN_EVCOUNT),
        "timecounter" => {
            mib.push(KERN_TIMECOUNTER);
            match names[1].as_str() {
                "tick" => mib.push(KERN_TIMECOUNTER_TICK),
                "timestepwarnings" => {
                    mib.push(KERN_TIMECOUNTER_TIMESTEPWARNINGS);
                    changeable = true;
                },
                "hardware" => {
                    mib.push(KERN_TIMECOUNTER_HARDWARE);
                    value_type = SysctlType::SysString;
                    changeable = true;
                },
                "choice" => {
                    mib.push(KERN_TIMECOUNTER_CHOICE);
                    value_type = SysctlType::SysString;
                },
                _ => return Err(Error::invalid_argument()),
            }
        },
        "maxlocksperuid" => {
            mib.push(KERN_MAXLOCKSPERUID);
            changeable = true;
        },
        "cp_time2" => {
            mib.push(KERN_CPTIME2);
            value_type = SysctlType::UInt64Slice;
        },
        "bufcachepercent" => {
            mib.push(KERN_CACHEPCT);
            changeable = true;
        },
        "file" => {
            mib.push(KERN_FILE);
            value_type = SysctlType::SysStruct;
        },
        "wxabort" => {
            mib.push(KERN_WXABORT);
            changeable = true;
        },
        "consdev" => {
            mib.push(KERN_CONSDEV);
            value_type = SysctlType::DevT;
        },
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
                "record" => {
                    mib.push(KERN_AUDIO_RECORD);
                    changeable = true;
                },
                _ => return Err(Error::invalid_argument()),
            }
        },
        _ => return Err(Error::invalid_argument()),
    };

    let res = Sysctl::new(mib, value_type, changeable)?;

    Ok(res)
}

fn parse_mib_vm(names: &[String]) -> Result<Sysctl> {
    let mut mib = vec![CTL_VM as c_int];
    let mut value_type = SysctlType::Int32;
    let mut changeable = false;

    match names[0].as_str() {
        "vmmeter" => {
            mib.push(VM_METER);
            value_type = SysctlType::SysStruct;
        },
        "loadavg" => {
            mib.push(VM_LOADAVG);
            value_type = SysctlType::SysStruct;
        },
        "psstrings" => {
            mib.push(VM_PSSTRINGS);
            value_type = SysctlType::SysStruct;
        },
        "uvmexp" => {
            mib.push(VM_UVMEXP);
            value_type = SysctlType::SysStruct;
        },
        "swapencrypt" => {
            mib.push(VM_SWAPENCRYPT);
            value_type = SysctlType::SysStruct;
            changeable = true;
        },
        "nkmempages" => mib.push(VM_NKMEMPAGES),
        "anonmin" => {
            mib.push(VM_ANONMIN);
            changeable = true;
        },
        "vtextmin" => {
            mib.push(VM_VTEXTMIN);
            changeable = true;
        },
        "vnodemin" => {
            mib.push(VM_VNODEMIN);
            changeable = true;
        },
        "maxslp" => mib.push(VM_MAXSLP),
        "uspace" => mib.push(VM_USPACE),
        "malloc_conf" => {
            mib.push(VM_MALLOC_CONF);
            value_type = SysctlType::SysString;
            changeable = true;
        },
        _ => return Err(Error::invalid_argument()),
    };

    let res = Sysctl::new(mib, value_type, changeable)?;

    Ok(res)
}

fn parse_mib_fs(names: &[String]) -> Result<Sysctl> {
    let mut mib = vec![CTL_FS as c_int];

    match names[0].as_str() {
        "posix" => {
            mib.push(FS_POSIX);
            match names[1].as_str() {
                "setuid" => mib.push(FS_POSIX_SETUID),
                _ => return Err(Error::invalid_argument()),
            }
        },
        _ => return Err(Error::invalid_argument()),
    };

    let res = Sysctl::new(mib, SysctlType::Int32, true)?;

    Ok(res)
}

fn parse_mib_net(names: &[String]) -> Result<Sysctl> {
    let mut mib = vec![CTL_NET as c_int];
    let mut value_type = SysctlType::Int32;
    let mut changeable = false;

    match names[0].as_str() {
        "route" => {
            mib.push(PF_ROUTE);
            // protocol number, always 0 for now
            mib.push(0);
            mib.push(get_addr_family(&names[2])?);
            match names[3].as_str() {
                "dump" => {
                    mib.push(NET_RT_DUMP);
                    if names.len() > 4 {
                        // TODO: get table from args
                        let table = 0;
                        mib.push(table);
                    } else {
                        mib.push(0);
                    }
                },
                "flags" => {
                    mib.push(NET_RT_FLAGS);
                    // TODO: push rtflags onto mib
                },
                "iflist" => mib.push(NET_RT_IFLIST),
                "ifnames" => mib.push(NET_RT_IFNAMES),
                "stats" => mib.push(NET_RT_STATS),
                "table" => mib.push(NET_RT_TABLE),
                _ => return Err(Error::invalid_argument()),
            }
        },
        // TODO: parse the args that can get passed here
        "inet" => {
            mib.push(PF_INET);
            changeable = true;
            match names[1].as_str() {
                "ah" => {
                    mib.push(IPPROTO_AH);
                    match names[2].as_str() {
                        "enable" => mib.push(1),
                        "stats" => mib.push(2),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "bpf" => {
                    mib.push(pseudo_AF_HDRCMPLT);
                    match names[2].as_str() {
                        "bufsize" => mib.push(1),
                        "maxbufsize" => mib.push(2),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "carp" => {
                    mib.push(IPPROTO_CARP);
                    match names[2].as_str() {
                        "allow" => mib.push(1),
                        "log" => mib.push(3),
                        "preempt" => mib.push(2),
                        "stats" => mib.push(4),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "divert" => {
                    mib.push(IPPROTO_DIVERT);
                    match names[2].as_str() {
                        "recvspace" => mib.push(1),
                        "sendspace" => mib.push(2),
                        "stats" => mib.push(3),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "esp" => {
                    mib.push(IPPROTO_ESP);
                    match names[2].as_str() {
                        "enable" => mib.push(1),
                        "udpencap" => mib.push(2),
                        "udpencap_port" => mib.push(3),
                        "stats" => mib.push(4),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "etherip" => {
                    mib.push(IPPROTO_ETHERIP);
                    match names[2].as_str() {
                        "allow" => mib.push(1),
                        "stats" => mib.push(2),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "gre" => {
                    mib.push(IPPROTO_GRE);
                    match names[2].as_str() {
                        "allow" => mib.push(1),
                        "wccp" => mib.push(2),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "icmp" => {
                    mib.push(IPPROTO_ICMP);
                    match names[2].as_str() {
                        "bmcastecho" => mib.push(2),
                        "errppslimit" => mib.push(3),
                        "maskrepl" => mib.push(1),
                        "rediraccept" => mib.push(4),
                        "redirtimeout" => mib.push(5),
                        "stats" => {
                            mib.push(7);
                            value_type = SysctlType::SysStruct;
                            changeable = false;
                        },
                        "tstamprepl" => mib.push(6),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "ip" => {
                    mib.push(IPPROTO_IP);
                    match names[2].as_str() {
                        "arpdown" => mib.push(40),
                        "arptimeout" => mib.push(39),
                        "directed-broadcast" => mib.push(6),
                        "encdebug" => mib.push(12),
                        "forwarding" => mib.push(1),
                        "ifq" => {
                            mib.push(30);
                            value_type = SysctlType::Node;
                            match names[3].as_str() {
                                "congestion" => mib.push(4),
                                "drops" => mib.push(3),
                                "len" => mib.push(1),
                                "maxlen" => mib.push(2),
                                _ => return Err(Error::invalid_argument()),
                            }
                        },
                        "ipsec-allocs" => mib.push(18),
                        "ipsec-auth-alg" => {
                            mib.push(26);
                            value_type = SysctlType::SysString;
                        },
                        "ipsec-bytes" => mib.push(20),
                        "ipsec-comp-alg" => {
                            mib.push(29);
                            value_type = SysctlType::SysString;
                        },
                        "ipsec-enc-alg" => {
                            mib.push(25);
                            value_type = SysctlType::SysString;
                        },
                        "ipsec-expire-acquire" => mib.push(14),
                        "ipsec-firstuse" => mib.push(24),
                        "ipsec-invalid-life" => mib.push(15),
                        "ipsec-pfs" => mib.push(16),
                        "ipsec-soft-allocs" => mib.push(17),
                        "ipsec-soft-bytes" => mib.push(19),
                        "ipsec-soft-firstuse" => mib.push(23),
                        "ipsec-soft-timeout" => mib.push(22),
                        "ipsec-timeout" => mib.push(21),
                        "maxqueue" => mib.push(11),
                        "mforwarding" => mib.push(31),
                        "mtudisc" => mib.push(27),
                        "mtudisctimeout" => mib.push(28),
                        "multipath" => mib.push(32),
                        "portfirst" => mib.push(7),
                        "pirthifirst" => mib.push(9),
                        "porthilast" => mib.push(10),
                        "portlast" => mib.push(8),
                        "redirect" => mib.push(2),
                        "sourceroute" => mib.push(5),
                        "stats" => {
                            mib.push(33);
                            value_type = SysctlType::SysStruct;
                            changeable = false;
                        },
                        "ttl" => mib.push(3),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "ipcomp" => {
                    mib.push(IPPROTO_IPCOMP);
                    match names[2].as_str() {
                        "enable" => mib.push(1),
                        "stats" => mib.push(2),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "ipip" => {
                    mib.push(IPPROTO_IPIP);
                    match names[2].as_str() {
                        "allow" => mib.push(1),
                        "stats" => mib.push(2),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "mobileip" => {
                    mib.push(IPPROTO_MOBILE);
                    match names[2].as_str() {
                        "allow" => mib.push(1),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "tcp" => {
                    mib.push(IPPROTO_TCP);
                    match names[2].as_str() {
                        "ackonpush" => mib.push(13),
                        "always_keepalive" => mib.push(16),
                        "baddynamic" => {
                            mib.push(6);
                            value_type = SysctlType::UInt32Slice;
                        },
                        "drop" => mib.push(19),
                        "ecn" => mib.push(14),
                        "ident" => {
                            mib.push(9);
                            value_type = SysctlType::SysStruct;
                            changeable = false;
                        },
                        "keepidle" => mib.push(3),
                        "keepinittime" => mib.push(2),
                        "keepintvl" => mib.push(4),
                        "mssdflt" => mib.push(11),
                        "reasslimit" => mib.push(18),
                        "rfc1323" => mib.push(1),
                        "rfc3390" => mib.push(17),
                        "rootonly" => {
                            mib.push(24);
                            value_type = SysctlType::UInt32Slice;
                        },
                        "rstppslimit" => mib.push(12),
                        "sack" => mib.push(10),
                        "sackholelimit" => mib.push(20),
                        "slowhz" => {
                            mib.push(5);
                            changeable = false;
                        },
                        "stats" => {
                            mib.push(21);
                            value_type = SysctlType::SysStruct;
                        },
                        "synbucketlimit" => mib.push(16),
                        "syncachelimit" => mib.push(15),
                        "synhashsize" => mib.push(25),
                        "synuselimit" => mib.push(23),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "udp" => {
                    mib.push(IPPROTO_UDP);
                    match names[2].as_str() {
                        "baddynamic" => {
                            mib.push(2);
                            value_type = SysctlType::UInt32Slice;
                        },
                        "checksum" => mib.push(1),
                        "recvspace" => mib.push(3),
                        "rootonly" => {
                            mib.push(6);
                            value_type = SysctlType::UInt32Slice;
                        },
                        "sendspace" => mib.push(4),
                        "stats" => {
                            mib.push(5);
                            value_type = SysctlType::SysStruct;
                            changeable = false;
                        },
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                _ => return Err(Error::invalid_argument()),
            }
        },
        "inet6" => {
            mib.push(PF_INET6);
            changeable = true;
            match names[1].as_str() {
                "divert" => {
                    mib.push(IPPROTO_DIVERT);
                    match names[2].as_str() {
                        "recvspace" => mib.push(1),
                        "sendspace" => mib.push(2),
                        "stats" => mib.push(3),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "icmp6" => {
                    mib.push(IPPROTO_ICMPV6);
                    match names[2].as_str() {
                        "errppslimit" => mib.push(14),
                        "mtudisc_hiwat" => mib.push(16),
                        "mtudisc_lowat" => mib.push(17),
                        "nd6_debug" => mib.push(18),
                        "nd6_delay" => mib.push(8),
                        "nd6_maxnudhint" => mib.push(15),
                        "nd6_maxtries" => mib.push(10),
                        "nd6_umaxtries" => mib.push(9),
                        "redirtimeout" => mib.push(17),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "ip6" => {
                    mib.push(IPPROTO_IPV6);
                    match names[2].as_str() {
                        "auto_flowlabel" => mib.push(17),
                        "dad_count" => mib.push(16),
                        "dad_pending" => mib.push(49),
                        "defmcasthlim" => mib.push(18),
                        "forwarding" => mib.push(1),
                        "hdrnestlimit" => mib.push(15),
                        "hlim" => mib.push(3),
                        "ifq" => {
                            mib.push(51);
                            value_type = SysctlType::Node;
                            changeable = false;
                        },
                        "log_interval" => mib.push(14),
                        "maxdynroutes" => mib.push(48),
                        "maxfragpackets" => mib.push(9),
                        "maxfrags" => mib.push(41),
                        "mforwarding" => mib.push(42),
                        "mtudisctimeout" => mib.push(50),
                        "multicast_mtudisc" => mib.push(44),
                        "multipath" => mib.push(43),
                        "neighborgcthresh" => mib.push(45),
                        "redirect" => mib.push(2),
                        "soiikey" => {
                            mib.push(54);
                            value_type = SysctlType::UInt8Slice;
                        },
                        "use_deprecated" => mib.push(21),
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                _ => return Err(Error::invalid_argument()),
            }
        },
        "key" => {
            mib.push(PF_KEY);
            match names[1].as_str() {
                "sadb_dump" => mib.push(1),
                "spd_dump" => mib.push(2),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "mpls" => {
            mib.push(PF_MPLS);
            changeable = true;
            match names[1].as_str() {
                //"ifq" => {
                //    mib.push(3);
                //    match names[2].as_str() {
                //        "congestion" => mib.push(4),
                //        "drops" => mib.push(3),
                //        "len" => mib.push(1),
                //        "maxlen" => mib.push(2),
                //        _ => return Err(Error::invalid_argument()),
                //    }
                //},
                "mapttl_ip" => mib.push(MPLSCTL_MAPTTL_IP),
                "mapttl_ip6" => mib.push(MPLSCTL_MAPTTL_IP6),
                "maxloop_inkernel" => mib.push(MPLSCTL_MAXINKLOOP),
                "ttl" => mib.push(MPLSCTL_DEFTTL),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "pipex" => {
            mib.push(PF_PIPEX);
            match names[1].as_str() {
                "enable" => {
                    mib.push(PIPEXCTL_ENABLE);
                    changeable = true;
                },
                "inq" => {
                    mib.push(PIPEXCTL_INQ);
                    match names[2].as_str() {
                        "ifq" => {
                            mib.push(30);
                            value_type = SysctlType::Node;
                            match names[3].as_str() {
                                "congestion" => mib.push(4),
                                "drops" => mib.push(3),
                                "len" => mib.push(1),
                                "maxlen" => mib.push(2),
                                _ => return Err(Error::invalid_argument()),
                            }
                        },
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                "outq" => {
                    mib.push(PIPEXCTL_OUTQ);
                    match names[3].as_str() {
                        "ifq" => {
                            mib.push(30);
                            value_type = SysctlType::Node;
                            match names[3].as_str() {
                                "congestion" => mib.push(4),
                                "drops" => mib.push(3),
                                "len" => mib.push(1),
                                "maxlen" => mib.push(2),
                                _ => return Err(Error::invalid_argument()),
                            }
                        },
                        _ => return Err(Error::invalid_argument()),
                    }
                },
                _ => return Err(Error::invalid_argument()),
            }
        },
        _ => return Err(Error::invalid_argument()),
    }

    let res = Sysctl::new(mib, value_type, changeable)?;

    Ok(res)
}

fn parse_mib_debug(names: &[String]) -> Result<Sysctl> {
    let mut mib = vec![CTL_DEBUG as c_int];
    let mut value_type = SysctlType::Int32;
    let mut changeable = false;

    match names[0].as_str() {
        "name" => mib.push(CTL_DEBUG_NAME),
        "value" => mib.push(CTL_DEBUG_VALUE),
        _ => return Err(Error::invalid_argument()),
    }

    let res = Sysctl::new(mib, value_type, changeable)?;

    Ok(res)
}

fn parse_mib_hw(names: &[String]) -> Result<Sysctl> {
    let mut mib = Vec::new();
    let mut value_type = SysctlType::Int32;
    let mut changeable = false;

    match names[0].as_str() {
        "machine" => {
            mib.push(HW_MACHINE);
            value_type = SysctlType::SysString;
        },
        "model" => {
            mib.push(HW_MODEL);
            value_type = SysctlType::SysString;
        },
        "ncpu" => mib.push(HW_NCPU),
        "byteorder" => mib.push(HW_BYTEORDER),
        // TODO: deprecated by 64-bit version for 64-bit CPUs?
        //"physmem" => mib.push(HW_PHYSMEM),
        //"usermem" => mib.push(HW_USERMEM),
        "pagesize" => mib.push(HW_PAGESIZE),
        "disknames" => {
            mib.push(HW_DISKNAMES);
            value_type = SysctlType::SysString;
        },
        "diskstats" => {
            mib.push(HW_DISKSTATS);
            value_type = SysctlType::SysStruct;
        },
        "diskcount" => mib.push(HW_DISKCOUNT),
        "sensors" => {
            mib.push(HW_SENSORS);
            value_type = SysctlType::Node;
        },
        "cpuspeed" => mib.push(HW_CPUSPEED),
        "setperf" => {
            mib.push(HW_SETPERF);
            changeable = true
        },
        "vendor" => {
            mib.push(HW_VENDOR);
            value_type = SysctlType::SysString;
        },
        "product" => {
            mib.push(HW_PRODUCT);
            value_type = SysctlType::SysString;
        },
        "version" => {
            mib.push(HW_VERSION);
            value_type = SysctlType::SysString;
        },
        "serialno" => mib.push(HW_SERIALNO),
        "uuid" => {
            mib.push(HW_UUID);
            value_type = SysctlType::SysString;
        },
        "physmem" => {
            mib.push(HW_PHYSMEM64);
            value_type = SysctlType::Int64;
        },
        "usermem" => {
            mib.push(HW_USERMEM64);
            value_type = SysctlType::Int64;
        },
        "npcufound" => mib.push(HW_NCPUFOUND),
        "allowpowerdown" => {
            mib.push(HW_ALLOWPOWERDOWN);
            changeable = true
        },
        "perfpolicy" => {
            mib.push(HW_PERFPOLICY);
            value_type = SysctlType::SysString;
            changeable = true;
        },
        "smt" => {
            mib.push(HW_SMT);
            changeable = true;
        },
        "ncpuonline" => mib.push(HW_NCPUONLINE),
        _ => return Err(Error::invalid_argument()),
    };

    let res = Sysctl::new(mib, value_type, changeable)?;

    Ok(res)
}

fn parse_mib_machdep(names: &[String]) -> Result<Sysctl> {
    let mut mib = vec![CTL_MACHDEP as c_int];

    // since these are machine-dependent, not every one will be available
    // on every piece of hardware, so I'm gonna just do amd64, which is the
    // only OpenBSD platform Rust builds on arfaict?
    match names[0].as_str() {
        "allowaperture" => mib.push(MACHDEP_ALLOWAPERTURE),
        "kbdreset" => mib.push(MACHDEP_KBDRESET),
        "lidaction" => mib.push(MACHDEP_LIDACTION),
        "pwraction" => mib.push(MACHDEP_PWRACTION),
        _ => return Err(Error::invalid_argument()),
    };

    let res = Sysctl::new(mib, SysctlType::Int32, true)?;

    Ok(res)
}

fn parse_mib_ddb(names: &[String]) -> Result<Sysctl> {
    let mut mib = vec![CTL_DDB as c_int];

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
    };

    let res = Sysctl::new(mib, SysctlType::Int32, true)?;

    Ok(res)
}

fn parse_mib_vfs(names: &[String]) -> Result<Sysctl> {
    let mut mib = vec![CTL_VFS as c_int];
    let mut value_type = SysctlType::Int32;
    let mut changeable = false;
match names[0].as_str() {
        // not sure where these consts live, just using what the tree walking
        // in modified sysctl(8) spits out
        "mounts" => mib.push(0),
        "ffs" => {
            mib.push(1);
            changeable = true;
            match names[1].as_str() {
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
                "dirhash_mem" => {
                    mib.push(FFS_DIRHASH_MEM);
                    changeable = false;
                },
                _ => return Err(Error::invalid_argument()),
            }
        },
        "nfs" => {
            mib.push(3);
            changeable = true;
            match names[1].as_str() {
                "nfsstats" => {
                    mib.push(NFS_NFSSTATS);
                    value_type = SysctlType::SysStruct;
                },
                "iothreads" => mib.push(NFS_NIOTHREADS),
                _ => return Err(Error::invalid_argument()),
            }
        },
        "mfs" => mib.push(4),
        "msdos" => mib.push(5),
        "ntfs" => mib.push(7),
        "udf" => mib.push(14),
        "cd9660" => mib.push(15),
        "ext2fs" => mib.push(18),
        "fuse" => {
            mib.push(19);
            match names[1].as_str() {
                "fusefs_open_devices" => mib.push(FUSEFS_OPENDEVS),
                "fusefs_fbufs_in" => mib.push(FUSEFS_INBUFS),
                "fusefs_fbufs_wait" => mib.push(FUSEFS_WAITBUFS),
                "fusefs_pool_pages" => mib.push(FUSEFS_POOL_NBPAGES),
                _ => return Err(Error::invalid_argument()),
            }
        },
        _ => return Err(Error::invalid_argument()),
    };

    let res = Sysctl::new(mib, value_type, changeable)?;

    Ok(res)
}

fn get_addr_family(name: &str) -> Result<c_int> {
    let af = match name {
        "unix" => AF_UNIX,
        "local" => AF_LOCAL,
        "inet" => AF_INET,
        "implink" => AF_IMPLINK,
        "pup" => AF_PUP,
        "chaos" => AF_CHAOS,
        "ns" => AF_NS,
        "iso" => AF_ISO,
        "osi" => AF_OSI,
        "ecma" => AF_ECMA,
        "datakit" => AF_DATAKIT,
        "ccitt" => AF_CCITT,
        "sna" => AF_SNA,
        "decnet" => AF_DECnet,
        "dli" => AF_DLI,
        "lat" => AF_LAT,
        "hylink" => AF_HYLINK,
        "appletalk" => AF_APPLETALK,
        "route" => AF_ROUTE,
        "link" => AF_LINK,
        "coip" => AF_COIP,
        "cnt" => AF_CNT,
        "ipx" => AF_IPX,
        "inet6" => AF_INET6,
        "isdn" => AF_ISDN,
        "e164" => AF_E164,
        "natm" => AF_NATM,
        "encap" => AF_ENCAP,
        "sip" => AF_SIP,
        "key" => AF_KEY,
        "bluetooth" => AF_BLUETOOTH,
        "mpls" => AF_MPLS,
        "0" => 0,
        _ => return Err(Error::invalid_argument()),
    };

    Ok(af)
}

impl Sysctl {
    fn new(mib: Vec<c_int>, value_type: SysctlType, changeable: bool) -> Result<Sysctl> {
        Ok(Sysctl {
            mib: mib,
            value_type: value_type,
            changeable: changeable,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn call_sysctl() {
        sysctl_read!(get_kern_ostype, "kern.ostype", Vec<u8>);

        let mut buf = vec![0u8; 256];
        unsafe { get_kern_ostype(&mut buf).unwrap() };
        buf.dedup_by(|a, b| *a == *b && *b == b'\0');

        assert_eq!(String::from_utf8(buf).unwrap().as_str(), "OpenBSD\0");
    }
}
