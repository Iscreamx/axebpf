//! Trace context passed to eBPF programs.

use crate::platform;

/// 传递给 eBPF 程序的追踪点上下文
///
/// 此结构体在追踪点触发时构造，作为 eBPF 程序的输入数据。
/// 必须与 eBPF 程序中的定义保持一致 (C ABI)。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceContext {
    /// 追踪点唯一标识
    pub tracepoint_id: u32,
    /// 触发时间戳 (纳秒)
    pub timestamp_ns: u64,
    /// VM ID (0 表示无关联)
    pub vm_id: u32,
    /// vCPU ID (0 表示无关联)
    pub vcpu_id: u32,
    /// 追踪点参数 0
    pub arg0: u64,
    /// 追踪点参数 1
    pub arg1: u64,
    /// 追踪点参数 2
    pub arg2: u64,
    /// 追踪点参数 3
    pub arg3: u64,
}

impl TraceContext {
    /// 创建新的追踪上下文
    pub fn new(tracepoint_id: u32) -> Self {
        Self {
            tracepoint_id,
            timestamp_ns: platform::time_ns(),
            ..Default::default()
        }
    }

    /// 设置 VM 信息
    pub fn with_vm(mut self, vm_id: u32, vcpu_id: u32) -> Self {
        self.vm_id = vm_id;
        self.vcpu_id = vcpu_id;
        self
    }

    /// 设置参数
    pub fn with_args(mut self, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> Self {
        self.arg0 = arg0;
        self.arg1 = arg1;
        self.arg2 = arg2;
        self.arg3 = arg3;
        self
    }

    /// 转换为字节数组 (用于传递给 eBPF VM)
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }

    /// 转换为可变字节数组
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self as *mut Self as *mut u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
