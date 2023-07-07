use std::{collections::HashSet, net::SocketAddr, rc::Rc};

use io_uring::{cqueue, opcode, squeue, types::Fd, Probe};
use nix::{
    errno::Errno,
    libc,
    sys::socket::{socket, AddressFamily, SockFlag, SockType, SockaddrLike},
    unistd,
};

use crate::ring::{EntryInfo, RingAllocator};
use crate::scan::{check_op_supported, PushError, RawFd, Scan, SockaddrIn, Timeouts};

pub struct ScanTcpConnect {
    set: HashSet<Rc<SockaddrIn>>,
}

// 枚举类型，表示 IO 请求的不同阶段
// 使用了 io_uring 异步 I/O 操作进行扫描。在扫描过程中，对于每个 IP 地址，都会创建三个异步操作
#[derive(Debug)]
enum EntryStep {
    Connect = 0,    // 向目标主机发起连接请求。
    ConnectTimeout, // 设置连接超时时间。
    Close,          // 关闭 socket 连接。
}

// u8 类型到 EntryStep 枚举类型的转换
impl From<u8> for EntryStep {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Connect,
            1 => Self::ConnectTimeout,
            2 => Self::Close,
            _ => unreachable!(),
        }
    }
}

impl ScanTcpConnect {
    pub fn new() -> Self {
        Self {
            set: HashSet::new(),
        }
    }
}

impl Scan for ScanTcpConnect {
    // 检查设备是否支持所需的操作
    fn check_supported(&self, probe: &Probe) -> bool {
        // 全部的opcode请看 https://docs.rs/io-uring/latest/io_uring/opcode/index.html
        check_op_supported(probe, opcode::Connect::CODE, "connect")
            && check_op_supported(probe, opcode::LinkTimeout::CODE, "link timeout")
            && check_op_supported(probe, opcode::Close::CODE, "close")
    }

    // 返回传输大小的最大值
    fn max_tx_size(&mut self) -> Option<usize> {
        None
    }

    // 返回每个 IP 地址的操作数
    fn ops_per_ip(&self) -> usize {
        3
    }

    // 处理已完成的 IO 请求
    fn process_completed_entry(
        &mut self,
        cq_entry: &cqueue::Entry,
        entry_info: &EntryInfo,
        ring_allocator: &RingAllocator,
    ) -> bool {
        // 获取当前IO请求状态
        let step = EntryStep::from(entry_info.step);
        // 将 IO 请求的返回值转换成 Errno 枚举类型，并记录到日志中
        let errno = Errno::from_i32(-cq_entry.result());
        log::debug!(
            "op #{} ({:?} {}) returned {} ({:?})",
            cq_entry.user_data(),
            step,
            entry_info.ip,
            cq_entry.result(),
            errno
        );

        if let Some(buf) = entry_info.buf.as_ref() {
            log::debug!(
                "buf: {:?}",
                String::from_utf8_lossy(ring_allocator.get_buf(buf.idx))
            );
        }

        match step {
            // Connect 请求完成
            EntryStep::Connect => {
                // 如果返回值为 0，表示连接成功
                let ret = cq_entry.result();
                if ret == 0 && !self.set.contains(&entry_info.ip) {
                    // 打印成功连接的 IP 地址
                    log::info!("{} \t delay: {}ms", &entry_info.ip, &entry_info.start.elapsed().as_millis());
                    self.set.insert(entry_info.ip.clone());
                }
                false
            }
            // 如果是 ConnectTimeout 状态，表示链接超时了
            EntryStep::ConnectTimeout => false,

            // 如果是Close ，说明断开链接了
            EntryStep::Close => {
                // 如果返回值为 -libc::ECANCELED，表示连接超时，需要关闭套接字
                if cq_entry.result() == -libc::ECANCELED {
                    unistd::close(entry_info.fd).unwrap();
                }
                true
            }
            _ => false,
        }
    }

    // 向扫描队列添加新的操作
    fn push_scan_ops(
        &mut self,
        sckt: RawFd, // 第一个参数，表示需要执行操作的 socket。RawFd 是 libc 库中定义的整型类型，用于表示文件描述符。
        addr: &SockaddrIn, // 第二个参数，表示需要连接的远程地址。
        squeue: &mut io_uring::squeue::SubmissionQueue, // 表示操作提交队列，用于向内核提交 IO 操作。
        allocator: &mut RingAllocator,                  // 表示分配的环形缓冲区中的 Entry 分配器。
        timeouts: &Timeouts,                            // 表示连接超时时间和读写超时时间。
    ) -> Result<usize, PushError> {
        // 如果一个函数尝试在接收到引用后持有 SockaddrIn 实例的所有权，而另一个函数在该函数持有实例的所有权之后仍然尝试访问该实例，就会出现未定义行为
        // 为了避免可能的生命周期问题，使用 Rc 引用计数智能指针可以方便而且安全地管理 SockaddrIn 实例的生命周期
        let addr = Rc::new(addr.to_owned()); // 将远程地址拷贝一份，并使用 Rc 包装。

        // 分配一个新的 Entry，表示 Connect 请求
        let entry_connect_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),           // 将 Rc 对象的引用计数增加 1。
                step: EntryStep::Connect as u8, // 元素枚举类型转换为 u8 类型。
                buf: None,                      // 不需要缓冲区的支持。
                fd: sckt,                       // socket 描述符。
                start: std::time::Instant::now(),
            })
            .unwrap(); // 如果分配失败，直接 panic 终止程序。

        // 创建 Connect 操作
        let op_connect = opcode::Connect::new(Fd(sckt), addr.as_ptr(), addr.len()) // 创建 Connect 操作。
            .build() // 构建操作,返回一个新的、不可变的操作对象。它的作用是将传递进来的参数进行格式化处理，准备好后续的异步IO操作
            .flags(squeue::Flags::IO_LINK) // 将操作标记为 IO_LINK，它的作用是将该操作与后续操作关联，以便可以在后续的事件处理中正确地处理它们之间的关系。例如，在某个事件触发时，可以通过该标志位来确定事件所对应的操作是哪个。
            .user_data(entry_connect_idx); // 将 Connect 操作对象与一个用户数据关联起来，以便在后续的事件处理中能够正确的获取到它。entry_connect_idx 可能是一个索引值，指向一个数组或其他数据结构中的某个元素，该元素与 Connect 操作对象相关联。

        // 分配一个新的 Entry，表示 ConnectTimeout 请求
        let entry_connect_timeout_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::ConnectTimeout as u8,
                buf: None,
                fd: sckt,
                start: std::time::Instant::now(),
            })
            .unwrap();

        // 创建 LinkTimeout 操作，设置连接超时时间，并与 Connect 操作关联
        let op_connect_timeout = opcode::LinkTimeout::new(&timeouts.connect) // 根据连接超时时间创建 LinkTimeout 操作。
            .build() // 构建操作。
            .flags(squeue::Flags::IO_LINK) // 将操作标记为 IO_LINK，表示这个操作与后续操作关联。
            .user_data(entry_connect_timeout_idx); // 设置该操作的 user_data 属性，并与 Connect 操作关联。

        // 分配一个新的 Entry，表示 Close 请求
        let entry_close_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Close as u8,
                buf: None,
                fd: sckt,
                start: std::time::Instant::now(),
            })
            .unwrap();

        // 创建 Close 操作，与 Connect 操作关联
        let op_close = opcode::Close::new(Fd(sckt)) // 创建 Close 操作。
            .build() // 构建操作。
            .user_data(entry_close_idx); // 设置 user_data 属性，并与 Connect 操作关联。

        let ops = [op_connect, op_connect_timeout, op_close]; // 创建三个操作的数组，表示一个扫描周期中需要执行的操作。

        unsafe {
            // 使用 unsafe 块进行内存操作。
            squeue
                .push_multiple(&ops) // 将创建的操作添加到 SubmissionQueue 中。
                .expect("Failed to push ops"); // 如果添加失败，则直接 panic 终止程序。
        }
        Ok(ops.len()) // 返回添加成功的操作数量。
    }

    // 创建一个 TCP 套接字
    fn socket(&self) -> RawFd {
        socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .expect("Failed to create TCP socket")
    }
}

// 笔记
// I/O uring 是 Linux 内核的一个异步 I/O 框架，它提供了一种高效的、事件驱动的编程模型，能够实现非阻塞 I/O 操作。与传统的 select/poll/epoll 模型不同，I/O uring 使用 I/O 触发器 (ring buffer) 和内核提交队列 (submission queue) 来管理异步 I/O，从而避免了多线程加锁、内核上下文切换等开销。

// 在 I/O uring 中，我们可以将一个操作 (operation) 和一个用户数据 (user data) 组成一个任务 (task)，然后将这些任务添加到内核提交队列中。当任务完成时，内核会将操作的结果返回给应用程序，并将用户数据一并返回。

// push_scan_ops 函数中，每个操作都会带有一个 user_data，这个 user_data 就是一个代表 Entry 的整数索引。当一个操作完成时，I/O uring 会触发一个 completion event，这个事件包含了操作的结果和相关的 user_data。应用程序可以通过 user_data 来区分不同的操作，从而确定操作的完成顺序。

// 在 push_scan_ops 中，Connect 操作、ConnectTimeout 操作和 Close 操作都被标记为 IO_LINK，将它们关联起来。这意味着它们必须按照指定顺序完成，否则 I/O uring 会自动取消那些还没有完成的操作。具体来说，当一个操作完成时，内核会检查是否有关联的操作未完成，如果有，则继续等待下一个 completion event 并处理它，直到所有关联的操作都完成为止。

// 在代码中，Connect 操作是第一个操作，最后一个操作是 Close 操作。这意味着连接必须先建立，然后才能进行扫描，而扫描完成后需要关闭 socket，释放资源。ConnectTimeout 操作是要等待连接的完成，如果连接超时，就会触发 ConnectTimeout 操作，使扫描能够及时终止。因此，三个操作之间的逻辑控制流是以一定顺序执行的，不会出现先执行了 Close 操作后执行 Connect 操作的情况。
