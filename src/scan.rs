//! Scan type specific logic

use std::os::unix::io::RawFd;

use io_uring::{
    cqueue,  // completion queue 类型
    squeue::{PushError, SubmissionQueue},  // submission queue 类型及其 push 方法可能产生的错误类型
    types::Timespec,  // Timespec 的类型定义
    Probe,  // io_uring 支持检测
};
use nix::sys::socket::SockaddrIn;  // 套接字地址类型

use crate::ring::{EntryInfo, RingAllocator};  // 自定义的引用类型

pub mod http_header_match;
pub mod ssh_version;
pub mod tcp_connect;

/// 超时时间的结构体，用于连接、读取和写入
pub struct Timeouts {
    pub connect: Timespec,
    pub read: Timespec,
    pub write: Timespec,
}

/// 网络扫描 trait
pub trait Scan {
    /// 检查当前内核是否支持 io_uring，如果不支持就返回False
    fn check_supported(&self, probe: &Probe)->bool;

    /// 返回需要发送的最大字节数，用于预先分配缓冲区
    fn max_tx_size(&mut self) -> Option<usize>;

    /// 返回需要扫描单个 IP 所需的 io_uring 操作次数
    fn ops_per_ip(&self) -> usize;

    /// 处理已完成的 io_uring 操作，返回是否完成了整个 IP 的扫描
    fn process_completed_entry(
        &mut self,
        cq_entry: &cqueue::Entry,
        entry_info: &EntryInfo,
        ring_allocator: &RingAllocator,
    ) -> bool;

    /// 推入 io_uring 操作以扫描对等 IP
    fn push_scan_ops(
        &mut self,
        sckt: RawFd,
        ip: &SockaddrIn,
        squeue: &mut SubmissionQueue,
        allocator: &mut RingAllocator,
        timeouts: &Timeouts,
    ) -> Result<usize, PushError>;

    /// 创建用于此扫描的套接字
    fn socket(&self) -> RawFd;
}

/// 检查操作是否被支持，如果不支持则产生 panic
fn check_op_supported(probe: &Probe, opcode: u8, name: &str) ->bool {
    let result = probe.is_supported(opcode);
    if !result{
        log::error!("This kernel does not support io_uring op code {} ({:?})",name,opcode);
    }
    return result;
}

/// 判断是否可以推入 io_uring 操作以扫描指定的 IP
pub fn can_push(squeue: &SubmissionQueue, scan: &dyn Scan, allocator: &RingAllocator) -> bool {
    let ops_per_ip = scan.ops_per_ip();
    // 判断是否有足够的空闲入口数
    allocator.has_free_entry_count(ops_per_ip) &&
    // 判断 submission queue 是否已满
    (squeue.capacity() - squeue.len() >= ops_per_ip)
}
