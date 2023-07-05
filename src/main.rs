#![feature(byte_slice_trim_ascii)]

use std::cmp::min;
use std::fmt::Write;
use std::io;
use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::time::Duration;

use indicatif::{HumanDuration, ProgressBar, ProgressState, ProgressStyle};
use io_uring::types::Timespec;
use io_uring::{IoUring, Probe};
use iprange::IpRange;
use nix::sys::{resource, socket::SockaddrIn};
use structopt::StructOpt;

use scan::http_header_match::ScanHttpHeaderMatch;
use scan::ssh_version::ScanSshVersion;
use scan::tcp_connect::ScanTcpConnect;
use scan::{can_push, Scan};

mod config;
mod ring;
mod scan;

fn main() -> io::Result<()> {
    // 初始化日志记录器
    // simple_logger::SimpleLogger::new()
    //     .init()
    //     .expect("Failed to init logger");
    simple_logger::init_with_env().unwrap();

    // 解析命令行参数
    let cl_opts: config::CommandLineOptions = config::CommandLineOptions::from_args();
    log::trace!("{:?}", cl_opts);

    // 增加打开文件数限制
    let (soft_limit, hard_limit) = resource::getrlimit(resource::Resource::RLIMIT_NOFILE).unwrap();
    resource::setrlimit(resource::Resource::RLIMIT_NOFILE, hard_limit, hard_limit).unwrap();
    log::info!("Bumped RLIMIT_NOFILE from {soft_limit} to {hard_limit}");

    // 创建一个 ring buffer
    let mut iorings = IoUring::new(cl_opts.ring_size as u32)?;

    // 根据命令行参数选择对应的扫描类型
    let mut scan: Box<dyn Scan> = match &cl_opts.scan_opts {
        config::ScanOptions::HttpHeaderMatch(scan_opts) => {
            Box::new(ScanHttpHeaderMatch::new(scan_opts))
        }
        config::ScanOptions::SshVersion(scan_opts) => Box::new(ScanSshVersion::new(scan_opts)),
        config::ScanOptions::TcpConnect(_) => Box::new(ScanTcpConnect::new()),
    };

    // 创建 Probe 并检查所选的扫描类型是否支持 io_uring 提供的操作
    let mut probe = Probe::new();
    iorings.submitter().register_probe(&mut probe)?;
    scan.check_supported(&probe);

    // 初始化 RingAllocator 以跟踪 ring buffer 的状态
    let mut ring_allocator = ring::RingAllocator::new(
        // cl_opts.ring_size,
        cl_opts.ring_size * scan.ops_per_ip(),
        cl_opts.max_read_size,
        scan.max_tx_size(),
        &iorings.submitter(),
    );

    // 生成将要扫描的 IP 列表，并为每个 IP 地址创建 SockaddrIn 结构表示地址
    // ip_ranges 是收集全部的 CIDRs 后再生成新的 CIDRs，顺便去重了
    let ip_ranges = cl_opts.ip_subnets.iter().copied().collect::<IpRange<_>>();
    let total_ip_count: usize = ip_ranges.iter().map(|r| r.hosts().count()).sum();
    let mut ip_iter = ip_ranges.iter().flat_map(|r| r.hosts());

    let progress = ProgressBar::new(total_ip_count as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template(
                "Scanning IPs {msg} {wide_bar} {pos}/{len} ({smoothed_per_sec}) ETA {smoothed_eta}",
            )
            .unwrap()
            .with_key(
                "smoothed_eta",
                |s: &ProgressState, w: &mut dyn Write| match (s.pos(), s.len()) {
                    (pos, Some(len)) => write!(
                        w,
                        "{:#}",
                        HumanDuration(Duration::from_millis(
                            (s.elapsed().as_millis() * (len as u128 - pos as u128) / (pos as u128))
                                as u64
                        ))
                    )
                    .unwrap(),
                    _ => write!(w, "-").unwrap(),
                },
            )
            .with_key(
                "smoothed_per_sec",
                |s: &ProgressState, w: &mut dyn Write| match (s.pos(), s.elapsed().as_millis()) {
                    (pos, elapsed_ms) if elapsed_ms > 0 => {
                        write!(w, "{:.2}/s", pos as f64 * 1000_f64 / elapsed_ms as f64).unwrap()
                    }
                    _ => write!(w, "-").unwrap(),
                },
            ),
    );

    // 创建超时选项
    let timeouts = scan::Timeouts {
        connect: Timespec::new().sec(cl_opts.timeout_connect_secs),
        read: Timespec::new().sec(cl_opts.timeout_read_secs),
        write: Timespec::new().sec(cl_opts.timeout_write_secs),
    };

    let mut done = false;
    // 进入 while 循环，只要 done 标志为 false，则继续循环。
    while !done {
        // 内部 while 循环中调用 `can_push` 函数，
        // 该函数用于检查 Ring Buffer 是否可以推入下一个操作，而不会阻塞。如果可以，则执行以下操作。
        while can_push(&iorings.submission(), &*scan, &ring_allocator) {
            // 调用 `ip_iter.next()` 从 IP 地址列表中获取下一个地址，
            if let Some(ip_addr) = ip_iter.next() {
                // 使用 SockaddrIn 结构体表示该 IP 地址和端口，
                let addr: SockaddrIn = SockaddrIn::from(SocketAddrV4::new(ip_addr, cl_opts.port));
                // 调用 `scan.socket()` 获取一个 socket 对象。
                let sckt = scan.socket();
                // 记录 socket id，用于调试。
                log::trace!("New socket: {}", sckt);

                // 执行 `scan.push_scan_ops` 方法，将 socket 和 SockaddrIn 对象推入 Ring Buffer 中，
                // 并设置超时选项，该方法在添加操作时可能会阻塞。
                scan.push_scan_ops(
                    sckt.as_raw_fd(),
                    &addr,
                    &mut iorings.submission(),
                    &mut ring_allocator,
                    &timeouts,
                )
                .expect("Failed to push ring ops");
                // 如果没有已经分配的空间，即整个Ring Buffer 都是空的
                // 则将 `done` 标志设置为 true，然后跳出内部 while 循环。
            } else if ring_allocator.allocated_entry_count() == 0 {
                done = true;
                break;
            } else {
                break;
            }
        }

        // 记录已经完成的操作数。
        let completed_count = iorings.completion().len();
        log::trace!("Completed count before wait: {completed_count}");

        // 调用 `iorings.submit_and_wait` 将 Ring Buffer 中未完成的事件提交到内核，
        // 并阻塞等待至少一个完成事件。
        iorings.submit_and_wait(min(
            cl_opts.ring_batch_size,
            ring_allocator.allocated_entry_count() - completed_count,
        ))?;

        // 输出当前完成任务数量。
        log::trace!("Completed count after wait: {}", iorings.completion().len());

        // 遍历完成的事件，调用 `scan.process_completed_entry` 处理完成的事件并更新进度条。
        for ce in iorings.completion() {
            // 调用 `ring_allocator.get_entry` 函数获取相关的扫描项，
            let entry: &ring::EntryInfo = ring_allocator.get_entry(ce.user_data()).unwrap();
            // 调用 `scan.process_completed_entry` 处理完成的事件并更新进度条。
            if scan.process_completed_entry(&ce, entry, &ring_allocator) {
                progress.inc(1);
            }
            // 调用 `ring_allocator.free_entry` 释放扫描项。
            ring_allocator.free_entry(ce.user_data());
        }
    }
    progress.finish();

    Ok(())
}
