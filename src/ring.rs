//! 追踪环形缓冲区和缓冲状态。

use std::ffi::c_void;
use std::os::unix::io::RawFd;
use std::rc::Rc;

use io_uring::Submitter;
pub use nix::libc::iovec;
use nix::sys::socket::SockaddrIn;

pub type EntryIdx = u64;

#[derive(Clone)]
pub struct EntryInfo {
    // 在这里，使用引用计数的目的是为了避免在多个 entry 中存储相同的 IP 地址时出现内存浪费或重复创建的情况。
    // 通过使用引用计数，多个 entry 或其他对象可以共享同一个 SockaddrIn 实例，并在所有者数量为 0 时正确地将其释放。
    pub ip: Rc<SockaddrIn>, // 使用引用计数来持有 SockaddrIn 类型的 IP 地址
    pub step: u8,           // 记录 I/O 操作执行的步骤
    pub buf: Option<BufferInfo>, // 缓冲信息
    pub fd: RawFd,          // 文件描述符
}

pub type BufferIdx = usize;

pub struct Buffer {
    pub idx: BufferIdx, // 缓冲区索引
    pub iov: iovec,     // nix 库中定义的 iovec 结构体，表示一个缓冲区数据 IO 向量
}

#[derive(Clone)]
pub struct BufferInfo {
    pub idx: BufferIdx,             // 缓冲区索引
    pub direction: BufferDirection, // 缓冲区使用方向
}

#[derive(Clone, Debug)]
pub enum BufferDirection {
    RX, // 接收方向
    TX, // 发送方向
}

pub struct RingAllocator {
    buffers: Vec<Vec<u8>>,           // 所有缓冲区的存储区
    rx_buf_size: usize,              // RX 缓冲区大小
    tx_buf_size: Option<usize>,      // TX 缓冲区大小
    entries: Vec<Option<EntryInfo>>, // 所有 entry（包括分配和未分配的）的存储区
    free_entry_idx: Vec<EntryIdx>,   // 未使用的 entry 的索引
    free_rx_buf_idx: Vec<BufferIdx>, // 未使用的 RX 缓冲区的索引
    free_tx_buf_idx: Vec<BufferIdx>, // 未使用的 TX 缓冲区的索引
}

impl RingAllocator {
    // 创建环形缓冲区分配器
    pub fn new(
        ring_size: usize,
        rx_buf_size: usize,
        tx_buf_size: Option<usize>,
        submitter: &Submitter,
    ) -> Self {
        // 初始化缓冲区列表
        let mut buffers = Vec::with_capacity(ring_size * 2);
        // 为 RX 分配 ring_size 个缓冲区
        buffers.append(&mut vec![vec![0; rx_buf_size]; ring_size]);
        // 如果 TX 缓冲区大小被指定，那么为 TX 分配 ring_size 个缓冲区
        if let Some(tx_buf_size) = tx_buf_size {
            buffers.append(&mut vec![vec![0; tx_buf_size]; ring_size]);
        }
        // 准备缓冲区 IO 向量
        let iovs: Vec<iovec> = buffers
            .iter_mut()
            .enumerate()
            .map(|(i, b)| iovec {
                iov_base: b.as_mut_ptr() as *mut c_void,
                iov_len: if i < ring_size {
                    rx_buf_size
                } else if let Some(tx_buf_size) = tx_buf_size {
                    tx_buf_size
                } else {
                    // 表明永远不会运行到这里，如果运行到这里说明出大问题了
                    unreachable!()
                },
            })
            .collect();

        // 使用 Submitter 来注册所有的缓冲区
        submitter
            .register_buffers(&iovs)
            .expect("Failed to register buffers");

        // 初始化分配器的数据结构
        Self {
            buffers,
            rx_buf_size,
            tx_buf_size,
            entries: vec![None; ring_size], // 所有 entry 初始都为空
            free_entry_idx: (0..ring_size as EntryIdx).collect(), // 所有 entry 都是未分配的
            free_rx_buf_idx: (0..ring_size).collect(), // 所有 RX 缓冲区都是未使用的
            free_tx_buf_idx: (ring_size..ring_size * 2).collect(), // 所有 TX 缓冲区都是未使用的
        }
    }

    // 获取给定索引的 entry 的信息
    pub fn get_entry(&self, idx: EntryIdx) -> Option<&EntryInfo> {
        self.entries[idx as usize].as_ref() // 如果该索引对应的 entry 是未分配状态，则返回None
                                            // .expect("Unallocated entry")
    }

    // 判断当前是否有足够的未分配 entry 数量
    pub fn has_free_entry_count(&self, count: usize) -> bool {
        self.free_entry_idx.len() >= count
    }


    // 获取已经分配的 entry 数量
    // `entries.capacity()` 返回 Ring Buffer 中 `entry` 的总数量。
    // `free_entry_idx.len()` 返回未被分配的 `entry` 的下标数量。
    // 两者之差即为已经分配的 `entry` 数量。
    pub fn allocated_entry_count(&self) -> usize {
        self.entries.capacity() - self.free_entry_idx.len()
    }

    // 释放指定的 entry，并且清除该 entry 中对应的缓冲区
    pub fn free_entry(&mut self, idx: EntryIdx) {
        if let Some(buf) = &self.entries[idx as usize].as_ref().unwrap().buf {
            // 检查并清除与该 entry 对应的缓冲区
            let buf = buf.clone();
            self.free_buf(&buf.direction, buf.idx);
        }
        log::trace!("Freeing entry #{idx}");
        // 将该 entry 加入未分配 entry 列表中
        self.free_entry_idx.push(idx);
        // 该 entry 对应的信息现在为 None
        self.entries[idx as usize] = None;
    }

    // 分配指定信息的 entry
    // 因为底层存储的是Vec类型，pop 会弹出末尾的元素
    pub fn alloc_entry(&mut self, info: EntryInfo) -> Option<EntryIdx> {
        match self.free_entry_idx.pop() {
            Some(idx) => {
                log::trace!("Allocating entry #{idx}");
                debug_assert!(self.entries[idx as usize].is_none());
                self.entries[idx as usize] = Some(info);
                Some(idx)
            }
            None => {
                log::trace!("No free entry");
                None
            }
        }
    }

    // 获取指定索引的缓冲区
    pub fn get_buf(&self, idx: BufferIdx) -> &Vec<u8> {
        &self.buffers[idx]
    }

    // 释放指定方向和索引的缓冲区
    pub fn free_buf(&mut self, direction: &BufferDirection, idx: BufferIdx) {
        log::trace!("Freeing {direction:?} buf #{idx}");
        match direction {
            BufferDirection::RX => &mut self.free_rx_buf_idx,
            BufferDirection::TX => &mut self.free_tx_buf_idx,
        }
        .push(idx)
    }

    // 分配一个指定方向和指定初始值的缓冲区
    pub fn alloc_buf(&mut self, direction: BufferDirection, init_val: Option<&[u8]>) -> Buffer {
        let idx = match direction {
            BufferDirection::RX => &mut self.free_rx_buf_idx,
            BufferDirection::TX => &mut self.free_tx_buf_idx,
        }
        .pop()
        .expect("No free buffers");

        let iov = iovec {
            iov_base: self.buffers[idx].as_mut_ptr().cast::<c_void>(),
            iov_len: match direction {
                BufferDirection::RX => self.rx_buf_size,
                BufferDirection::TX => self.tx_buf_size.expect("TX buffer size was not set"),
            },
        };

        log::trace!("Allocating {direction:?} buf #{idx}: {iov:?}");

        if let Some(init_val) = init_val {
            self.buffers[idx][..init_val.len()].copy_from_slice(init_val);
        }

        Buffer { idx, iov }
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {

    use super::*;
    use io_uring::{IoUring, Submitter};
    use nix::sys::socket::SockaddrIn;
    use std::ffi::c_void;
    use std::os::unix::io::RawFd;
    use std::rc::Rc;
    use std::sync::Arc;

    fn test_default(
        ring_size: Option<usize>,
        rx_buf_size: Option<usize>,
        tx_buf_size: Option<usize>,
    ) -> (RingAllocator, IoUring) {
        let mut iorings = IoUring::new(12).unwrap();

        let allocator = RingAllocator::new(
            ring_size.unwrap_or(10),
            rx_buf_size.unwrap_or(1024),
            Some(tx_buf_size.unwrap_or(1024)),
            &iorings.submitter(),
        );

        (allocator, iorings)
    }

    #[test]
    fn test_ring_allocator_new() {
        let ring_size = 8;
        let rx_buf_size = 512;
        let tx_buf_size = 512;
        let (allocator, _) = test_default(Some(ring_size), Some(rx_buf_size), Some(tx_buf_size));

        assert_eq!(allocator.buffers.len(), ring_size * 2);
        assert_eq!(allocator.rx_buf_size, rx_buf_size);
        assert_eq!(allocator.tx_buf_size.unwrap(), tx_buf_size);
        assert_eq!(allocator.entries.len(), ring_size);
        assert_eq!(allocator.free_entry_idx.len(), ring_size);
        assert_eq!(allocator.free_rx_buf_idx.len(), ring_size);
        assert_eq!(allocator.free_tx_buf_idx.len(), ring_size);
    }

    #[test]
    fn test_ring_allocator_get_entry() {
        let (mut allocator, _) = test_default(None, None, None);

        let entry_info = EntryInfo {
            ip: Rc::new(SockaddrIn::new(127, 0, 0, 1, 0)),
            step: 0,
            buf: None,
            fd: -1,
        };
        let entry_idx = allocator.alloc_entry(entry_info.clone()).unwrap();

        let retrieved_entry_info = allocator.get_entry(entry_idx).unwrap();
        assert_eq!(retrieved_entry_info.ip, entry_info.ip);
        assert_eq!(retrieved_entry_info.step, entry_info.step);
        assert_eq!(retrieved_entry_info.buf.is_none(), entry_info.buf.is_none());
        assert_eq!(retrieved_entry_info.fd, entry_info.fd);
    }

    #[test]
    fn test_ring_allocator_has_free_entry_count() {
        let ring_size = 8;
        let (allocator, _) = test_default(Some(ring_size), None, None);

        assert!(allocator.has_free_entry_count(ring_size));
        assert!(!allocator.has_free_entry_count(ring_size + 1));
    }

    #[test]
    fn test_ring_allocator_allocated_entry_count() {
        let (mut allocator, _) = test_default(None, None, None);

        let entry_info = EntryInfo {
            ip: Rc::new(SockaddrIn::new(127, 0, 0, 1, 0)),
            step: 0,
            buf: None,
            fd: -1,
        };

        allocator.alloc_entry(entry_info.clone()).unwrap();
        assert_eq!(allocator.allocated_entry_count(), 1);

        allocator.alloc_entry(entry_info.clone()).unwrap();
        assert_eq!(allocator.allocated_entry_count(), 2);
    }

    #[test]
    fn test_ring_allocator_free_entry() {
        let ring_size = 8;
        let (mut allocator, _) = test_default(Some(ring_size), None, None);

        let entry_info = EntryInfo {
            ip: Rc::new(SockaddrIn::new(127, 0, 0, 1, 0)),
            step: 0,
            buf: None,
            fd: -1,
        };
        let entry_idx = allocator.alloc_entry(entry_info.clone()).unwrap();

        allocator.free_entry(entry_idx);
        assert_eq!(allocator.get_entry(entry_idx).is_none(), true);
        assert_eq!(allocator.free_entry_idx.len(), ring_size);
    }

    // 测试分配新条目
    #[test]
    fn test_ring_allocator_alloc_entry() {
        let ring_size = 8;
        let (mut allocator, _) = test_default(Some(ring_size), None, None);

        let entry_info = EntryInfo {
            ip: Rc::new(SockaddrIn::new(127, 0, 0, 1, 0)),
            step: 0,
            buf: None,
            fd: -1,
        };

        for i in 0..ring_size {
            // 注意！因为Vec.pop 弹出的是末尾元素
            // 所以索引应该是从ring_size - 1 到 0
            let entry_idx = allocator.alloc_entry(entry_info.clone()).unwrap();
            assert_eq!(entry_idx as usize, ring_size - i -1);
        }

        // 所有条目都已分配
        assert_eq!(allocator.has_free_entry_count(ring_size), false);

        // 尝试分配一个新条目时应该失败
        let result = allocator.alloc_entry(entry_info.clone());
        assert_eq!(result.is_none(), true);
    }
}
