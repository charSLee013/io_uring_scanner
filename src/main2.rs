extern crate ipnet;
extern crate iprange;

use ipnet::{Ipv4Net, Ipv4AddrRange};
use iprange::IpRange;
use std::net::Ipv4Addr;

fn main() {
        let ip_range: IpRange<Ipv4Net> = ["192.168.1.12/28", "192.168.1.129/30"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

    let mut total = 0;
    println!("{:?}",ip_range);
    for ip in ip_range.iter().flat_map(|r| r.hosts()) {
        println!("{}", ip);
        total += 1;
    }
    println!("All host num {}",total);
}
