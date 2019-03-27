use libc::c_int;

pub(crate) trait SysctlValue {
    fn to_sysctl(&self) -> &[c_int];

    fn from_sysctl(value: &[c_int]) -> Self;
}

impl SysctlValue for i32 {
    fn to_sysctl(&self) -> &[c_int] {
        unimplemented!()
    }

    fn from_sysctl(value: &[c_int]) -> i32 {
        unimplemented!()
    }
}

impl SysctlValue for i64 {
    fn to_sysctl(&self) -> &[c_int] {
        unimplemented!()
    }

    fn from_sysctl(value: &[c_int]) -> i64 {
        unimplemented!()
    }
}

impl SysctlValue for String {
    fn to_sysctl(&self) -> &[c_int] {
        unimplemented!()
    }

    fn from_sysctl(value: &[c_int]) -> String {
        unimplemented!()
    }
}

impl SysctlValue for u64 {
    fn to_sysctl(&self) -> &[c_int] {
        unimplemented!()
    }

    fn from_sysctl(value: &[c_int]) -> u64 {
        unimplemented!()
    }
}
