use std::{net::UdpSocket, os::fd::AsRawFd, time::Duration};

use aya::{
    maps::{Array, CpuMap, XskMap},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use object::{Object, ObjectSection, ObjectSymbol, SymbolSection};
use test_log::test;

use crate::utils::NetNsGuard;

#[test]
fn af_xdp() {
    let _netns = NetNsGuard::new();

    let mut bpf = Bpf::load(crate::REDIRECT).unwrap();
    let mut socks: XskMap<_> = bpf.take_map("SOCKS").unwrap().try_into().unwrap();

    let xdp: &mut Xdp = bpf
        .program_mut("redirect_sock")
        .unwrap()
        .try_into()
        .unwrap();
    xdp.load().unwrap();
    xdp.attach("lo", XdpFlags::default()).unwrap();

    use xsk_rs::{
        config::{LibbpfFlags, SocketConfigBuilder},
        Socket, Umem,
    };

    let (umem, mut descs) = Umem::new(Default::default(), 32.try_into().unwrap(), false).unwrap();
    let sk_cfg = SocketConfigBuilder::new()
        .libbpf_flags(LibbpfFlags::XSK_LIBBPF_FLAGS_INHIBIT_PROG_LOAD)
        .build();
    let (_tx, mut rx, fq_cq) = Socket::new(sk_cfg, &umem, &"lo".parse().unwrap(), 0).unwrap();
    let (mut fq, _cq) = fq_cq.unwrap();
    socks.set(0, rx.fd().as_raw_fd(), 0).unwrap();

    // SAFETY: descs are from the same umem as the socket is tied to
    // (valid for all further unsafe)
    unsafe { fq.produce(&descs) };

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    sock.send_to(b"hello AF_XDP", "127.0.0.1:1777").unwrap();

    let n = unsafe { rx.consume(&mut descs) };
    assert_eq!(n, 1);

    let data = unsafe { umem.data(&descs[0]) };
    let buf = data.contents();
    let (eth, buf) = buf.split_at(14);
    assert_eq!(eth[12..14], [0x08, 0x00]); // IP
    let (ip, buf) = buf.split_at(20);
    assert_eq!(ip[9], 17); // UDP
    let (udp, payload) = buf.split_at(8);
    assert_eq!(&udp[0..2], port.to_be_bytes().as_slice()); // Source
    assert_eq!(&udp[2..4], 1777u16.to_be_bytes().as_slice()); // Dest
    assert_eq!(payload, b"hello AF_XDP");
}

#[test]
fn prog_sections() {
    let obj_file = object::File::parse(crate::XDP_SEC).unwrap();

    ensure_symbol(&obj_file, "xdp", "xdp_plain");
    ensure_symbol(&obj_file, "xdp.frags", "xdp_frags");
    ensure_symbol(&obj_file, "xdp/cpumap", "xdp_cpumap");
    ensure_symbol(&obj_file, "xdp/devmap", "xdp_devmap");
    ensure_symbol(&obj_file, "xdp.frags/cpumap", "xdp_frags_cpumap");
    ensure_symbol(&obj_file, "xdp.frags/devmap", "xdp_frags_devmap");
}

#[track_caller]
fn ensure_symbol(obj_file: &object::File, sec_name: &str, sym_name: &str) {
    let sec = obj_file.section_by_name(sec_name).unwrap_or_else(|| {
        let secs = obj_file
            .sections()
            .flat_map(|sec| sec.name().ok().map(|name| name.to_owned()))
            .collect::<Vec<_>>();
        panic!("section {sec_name} not found. available sections: {secs:?}");
    });
    let sec = SymbolSection::Section(sec.index());

    let syms = obj_file
        .symbols()
        .filter(|sym| sym.section() == sec)
        .filter_map(|sym| sym.name().ok())
        .collect::<Vec<_>>();
    assert!(
        syms.contains(&sym_name),
        "symbol not found. available symbols in section: {syms:?}"
    );
}

#[test]
fn map_load() {
    let bpf = Bpf::load(crate::XDP_SEC).unwrap();

    bpf.program("xdp_plain").unwrap();
    bpf.program("xdp_frags").unwrap();
    bpf.program("xdp_cpumap").unwrap();
    bpf.program("xdp_devmap").unwrap();
    bpf.program("xdp_frags_cpumap").unwrap();
    bpf.program("xdp_frags_devmap").unwrap();
}

#[test]
fn cpumap_chain() {
    let _netns = NetNsGuard::new();

    let mut bpf = Bpf::load(crate::REDIRECT).unwrap();

    // Load our cpumap and our canary map
    let mut cpus: CpuMap<_> = bpf.take_map("CPUS").unwrap().try_into().unwrap();
    let hits: Array<_, u32> = bpf.take_map("HITS").unwrap().try_into().unwrap();

    let xdp_chain_fd = {
        // Load the chained program to run on the target CPU
        let xdp: &mut Xdp = bpf
            .program_mut("redirect_cpu_chain")
            .unwrap()
            .try_into()
            .unwrap();
        xdp.load().unwrap();
        xdp.fd().unwrap()
    };
    cpus.set(0, 2048, Some(xdp_chain_fd), 0).unwrap();

    // Load the main program
    let xdp: &mut Xdp = bpf.program_mut("redirect_cpu").unwrap().try_into().unwrap();
    xdp.load().unwrap();
    xdp.attach("lo", XdpFlags::default()).unwrap();

    const PAYLOAD: &str = "hello cpumap";

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    sock.send_to(PAYLOAD.as_bytes(), addr).unwrap();

    // Read back the packet to ensure it went through the entire network stack, including our two
    // probes.
    let mut buf = [0u8; PAYLOAD.len() + 1];
    let n = sock.recv(&mut buf).unwrap();

    assert_eq!(&buf[..n], PAYLOAD.as_bytes());
    assert_eq!(hits.get(&0, 0).unwrap(), 1);
    assert_eq!(hits.get(&1, 0).unwrap(), 1);
}
