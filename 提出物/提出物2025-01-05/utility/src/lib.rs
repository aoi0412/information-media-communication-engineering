// ここで実装するもの
// パケットの作成
// - 具体的にはICMPパケットのヘッダーを作成する
// タイプ（8bit）,コード(8bit),チェックサム(16bit),識別子(乱数生成),シークエンス(実行毎にカウントアップ),データ(一旦testで固定)
// 型としては符号なし8bit列であるu8を使用

/*
1. 一度チェックサムなしのパケットを作成（Vec<u8>）
2. チェックサムなしのパケットをビット列にしてから1の数を数える
3. 1の数をバイトに変換
4. バイトに変換したものを1の補数に変換
*/

use regex::Regex;
use std::f32;
use std::net::{Ipv4Addr, IpAddr, UdpSocket, SocketAddrV4};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType,TransportSender,TransportReceiver};



pub fn check_ipv4_address(input: &String) -> Result<Ipv4Addr,String> {
    let ipaddress_regex = Regex::new(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$").unwrap();
    let result = ipaddress_regex.is_match(input);
    if !result {
        println!("please input with format of IPv4 address");
        Err(String::from("IPアドレスの形式が正しくありません。"))
    } else {
        let ipaddress_u8:Vec<u8> = input.split(".").map(|s| s.parse::<u8>().unwrap()).collect();
        if ipaddress_u8.len() == 4 {
            let ipaddress: Ipv4Addr = Ipv4Addr::new(ipaddress_u8[0],ipaddress_u8[1],ipaddress_u8[2],ipaddress_u8[3]);
            Ok(ipaddress)
        } else {
            println!("please input with format of IPv4 address");
            Err(String::from("IPアドレスの形式が正しくありません。"))
        }
    }
}

pub fn get_source_ipv4(destination_ipv4:Ipv4Addr)->Result<Ipv4Addr,String>{
    let socket = SocketAddrV4::new(destination_ipv4, 80);
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect(socket.to_string()).unwrap();
    let tmp_ipv4:IpAddr = sock.local_addr().unwrap().ip();
    let source_ipv4: Ipv4Addr = match tmp_ipv4 {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => panic!("IPv6は扱えません"),
    };
    Ok(source_ipv4)
}

// TTLも引数から指定できるようにする
pub struct CreateIpv4PacketArgs {
    pub destination_ipv4: Ipv4Addr,
    pub source_ipv4:Ipv4Addr,
    pub identification:u16,
    pub ttl:u8,
    pub payload:Vec<u8>,
    pub df:bool,
    pub mode: String
}

impl Default for CreateIpv4PacketArgs {
    fn default() -> Self {
        CreateIpv4PacketArgs {
            destination_ipv4: "127.0.0.1".parse().unwrap(),
            source_ipv4:"127.0.0.1".parse().unwrap(),
            identification: 0,
            ttl: 64,
            payload: b"defalut payload".to_vec(),
            df: false,
            mode: "simple".to_string()
        }
    }
}
pub fn create_ipv4_packet(args:CreateIpv4PacketArgs) -> Result<Vec<u8>, String> {
    
    let header_len = 20;
    let mut ipv4_packet:Vec<u8> = Vec::<u8>::new();

    let tmp_version:u8 = 4;
    let tmp_header_length: u8 = 5;
    let tmp_dscp:u8 = 0;
    let tmp_ecn:u8 = 0;
    let tmp_packet_length:u16 = (header_len + args.payload.len()) as u16;
    let tmp_df: u8 = if args.df {
        1
    } else {
        0
    };
    let tmp_mf: u8 = 0;
    let tmp_frags: u8 = tmp_df << 1 | tmp_mf;
    let mut tmp_fragment_offset: u16 = 0;
    let tmp_ttl: u8 = args.ttl;
    let tmp_protocol_num: u8 = 1; // ICMPプロトコル = 1
    let mut tmp_checksum: u16 = 0;
    let checksum_frag1: usize;
    let checksum_frag2: usize;
    let tmp_destination: u32 = args.destination_ipv4.to_bits();
    let tmp_source: u32 = args.source_ipv4.to_bits();

    ipv4_packet.push((tmp_version << 4) | tmp_header_length);
    ipv4_packet.push((tmp_dscp << 2) | tmp_ecn);
    ipv4_packet.push((tmp_packet_length >> 8) as u8);
    ipv4_packet.push((tmp_packet_length & 0xff) as u8);
    ipv4_packet.push((args.identification >> 8) as u8);
    ipv4_packet.push((args.identification & 0xff) as u8);
        tmp_fragment_offset = tmp_fragment_offset & 0x1FFF;
    ipv4_packet.push((tmp_frags << 5) | (tmp_fragment_offset >> 8) as u8);
    ipv4_packet.push((tmp_fragment_offset & 0xff) as u8);
    ipv4_packet.push(tmp_ttl);
    ipv4_packet.push(tmp_protocol_num);
    ipv4_packet.push((tmp_checksum >> 8) as u8);
    checksum_frag1 = ipv4_packet.len() - 1;
    ipv4_packet.push((tmp_checksum & 0xff) as u8);
    checksum_frag2 = ipv4_packet.len() - 1;
    ipv4_packet.extend_from_slice(&tmp_source.to_be_bytes().to_vec());
    ipv4_packet.extend_from_slice(&tmp_destination.to_be_bytes().to_vec());

    // create checksum
    let mut for_checksum_vec:Vec<u16> = Vec::<u16>::new();
    ipv4_packet.chunks(2).for_each(|chunk| {
        let tmp_u16: u16 = if chunk.len() == 2 {
            (chunk[0] as u16) << 8 | chunk[1] as u16
        } else {
            (chunk[0] as u16) << 8
        };
        for_checksum_vec.push(tmp_u16);
    });
    // insert checksum
    tmp_checksum = create_checksum(for_checksum_vec)?;
    ipv4_packet[checksum_frag1] = (tmp_checksum >> 8) as u8;
    ipv4_packet[checksum_frag2] = (tmp_checksum & 0xff) as u8;
    if args.mode == "detail"{
        println!("↓IPv4ヘッダ");
        println!("チェックサム生成 → 0x{:x}→ 0x{:x}:0x{:x}\n", !(tmp_checksum as u16), (tmp_checksum >> 8) as u8, (tmp_checksum & 0xff) as u8);

        println!("送信パケット(IPv4ヘッダ 0x):{:x?}", ipv4_packet);
        println!("送信パケット(ICMPヘッダ 0x):{:x?}", args.payload);
    }


    ipv4_packet.extend_from_slice(&args.payload);

    Ok(ipv4_packet)
}


pub struct CreateIcmpPacketArgs {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub identification:u16,
    pub icmp_seq:u16,
    pub payload:String,
    pub mode: String
}

impl Default for CreateIcmpPacketArgs {
    fn default() -> Self {
        CreateIcmpPacketArgs {
            icmp_type: 8,
            icmp_code: 0,
            identification: 0,
            icmp_seq: 0,
            payload: "defalut payload".to_string(),
            mode: "simple".to_string()
        }
    }
}
pub fn create_icmp_packet(args: CreateIcmpPacketArgs) -> Result<Vec<u8>,String>{
    let mut for_checksum_vec = Vec::<u16>::new();
    let icmp_checksum: u16 = 0;
    let mut icmp_data:Vec<u8> = args.payload.as_bytes().to_vec();

    //// チェックサム用にVec<u16>を作成し、チェックサムを生成
    // タイプとコードを連結
    for_checksum_vec.push((args.icmp_type as u16) << 8 | args.icmp_code as u16);

    //チェックサムを連結
    for_checksum_vec.push(icmp_checksum);

    // 識別子とシークエンスを連結
    for_checksum_vec.push(args.identification);
    for_checksum_vec.push(args.icmp_seq);

    // ペイロードを連結
    icmp_data
    .chunks(2)
    .for_each(|chunk| {
        let tmp_u16: u16 = if chunk.len() == 2 {
            (chunk[0] as u16) << 8 | chunk[1] as u16
        } else {
            (chunk[0] as u16) << 8
        };
        for_checksum_vec.push(tmp_u16);
    });

    let icmp_checksum = create_checksum(for_checksum_vec)?;
    if args.mode == "detail"{
        println!("↓ICMPヘッダ");
        println!("チェックサム生成 → 0x{:x}→ 0x{:x}:0x{:x}\n", !(icmp_checksum as u16), (icmp_checksum >> 8) as u8, (icmp_checksum & 0xff) as u8);
    }
    
    //// ICMPパケットを生成
    let mut icmp_packet:Vec<u8> = Vec::<u8>::new();
    icmp_packet.push(args.icmp_type);
    icmp_packet.push(args.icmp_code);
    icmp_packet.push((icmp_checksum >> 8) as u8);
    icmp_packet.push((icmp_checksum & 0xff) as u8);
    icmp_packet.push((args.identification >> 8) as u8);
    icmp_packet.push((args.identification & 0xff) as u8);
    icmp_packet.push((args.icmp_seq >> 8) as u8);
    icmp_packet.push((args.icmp_seq & 0xff) as u8);
    icmp_packet.append(&mut icmp_data);

    Ok(icmp_packet)
}

pub fn create_checksum(for_checksum_vec:Vec<u16>)->Result<u16,String>{
    let mut sum:u32 = 0;
    for_checksum_vec.into_iter().for_each(|tmp|{
        sum = sum + tmp as u32;
    });
    while (sum >> 16) != 0 {
        // 下位16桁を取り出して、取り出した16桁に上位16桁を足す
        sum = (sum & 0xffff) + (sum >> 16);
    }


    // 反転したものを返す
    Ok(!(sum as u16))
}

pub fn create_socket()->Result<(TransportSender, TransportReceiver),String>{
    let (sender, receiver) = transport_channel(4096, TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp)).map_err(|e| format!("open channel failed: {e}"))?;
    Ok((sender, receiver))
}

pub fn send_ipv4_packet(sender:&mut TransportSender,destination_ipv4:Ipv4Addr,ipv4_packet:&[u8])->Result<()
,String>{
    let send_packet = Ipv4Packet::new(ipv4_packet)
        .ok_or_else(|| "invalid IPv4 bytes".to_string())?;
    sender.send_to(send_packet, IpAddr::V4(destination_ipv4)).map_err(|e| format!("send failed: {e}"))?;
    Ok(())
}

pub fn check_checksum(for_checksum_vec:Vec<u8>)->Result<u32, String>{
    let mut sum:u32 = 0;
    for_checksum_vec.chunks(2).for_each(|chunk| {
        let tmp_u16: u16 = if chunk.len() == 2 {
            (chunk[0] as u16) << 8 | chunk[1] as u16
        } else {
            (chunk[0] as u16) << 8
        };
        sum = sum + tmp_u16 as u32;
    });

    while (sum >> 16) != 0 {
        // 下位16桁を取り出して、取り出した16桁に上位16桁を足す
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if sum == 0xffff{
        Ok(sum)
    }else{
        println!("チェックサムの検証に失敗しました");
        Ok(sum)
    }
}

pub fn calc_stats(values: &[f32]) -> Result<(f32, f32, f32, f32),String> {
    if values.is_empty() {
        return Err("結果がありませんでした。".to_string());
    }

    let mut min = f32::INFINITY;
    let mut max = f32::NEG_INFINITY;
    let mut sum = 0.0;

    for &v in values {
        if v < min { min = v; }
        if v > max { max = v; }
        sum += v;
    }

    let avg = sum / values.len() as f32;

    let mut var_sum = 0.0;
    for &v in values {
        let diff = v - avg;
        var_sum += diff * diff;
    }
    let stddev = (var_sum / values.len() as f32).sqrt();

    Ok((min, avg, max, stddev))
}