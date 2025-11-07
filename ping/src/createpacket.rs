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
use std::net::{Ipv4Addr, IpAddr, UdpSocket, SocketAddrV4};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::Packet;
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

pub fn create_ipv4_packet(destination_ipv4:Ipv4Addr,source_ipv4:Ipv4Addr,identification:u16, payload: Vec<u8>) -> Result<Vec<u8>, String> {
    let header_len = 20;
    let packet_buf = vec![0u8; header_len + &payload.len()];
    let mut mut_ipv4_packet = MutableIpv4Packet::owned(packet_buf)
        .ok_or_else(|| String::from("IPv4パケット用のバッファ確保に失敗しました。"))?;
    mut_ipv4_packet.set_version(4);
    mut_ipv4_packet.set_header_length(5);
    mut_ipv4_packet.set_dscp(0);
    mut_ipv4_packet.set_ecn(0);
    mut_ipv4_packet.set_total_length((header_len + payload.len()) as u16);
    mut_ipv4_packet.set_identification(identification);
    mut_ipv4_packet.set_flags(0);
    mut_ipv4_packet.set_fragment_offset(0);
    mut_ipv4_packet.set_ttl(64);
    mut_ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    mut_ipv4_packet.set_checksum(0);
    mut_ipv4_packet.set_source(source_ipv4);
    mut_ipv4_packet.set_destination(destination_ipv4);
    mut_ipv4_packet.set_payload(&payload);
    

    let ipv4_checksum = checksum(&Ipv4Packet::new(mut_ipv4_packet.packet()).unwrap());
    mut_ipv4_packet.set_checksum(ipv4_checksum);

    // パケットの中身を出力
    let bytes = mut_ipv4_packet.packet().to_vec();
    Ok(bytes)
}

pub fn create_icmp_packet(icmp_type: u8, icmp_code: u8, icmp_data:String, identification:u16, icmp_seq:u16) -> Result<Vec<u8>,String>{
    let mut for_checksum_vec = Vec::<u16>::new();
    let mut icmp_checksum: u16 = 0;
    let mut icmp_data:Vec<u8> = icmp_data.into_bytes();

    //// チェックサム用にVec<u16>を作成し、チェックサムを生成
    // タイプとコードを連結
    for_checksum_vec.push((icmp_type as u16) << 8 | icmp_code as u16);

    //チェックサムを連結
    for_checksum_vec.push(icmp_checksum);

    // 識別子とシークエンスを連結
    for_checksum_vec.push(identification);
    for_checksum_vec.push(icmp_seq);

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

    let checksum_result:Result<u16,String> = create_icmp_checksum(for_checksum_vec);
    match checksum_result {
        Ok(value) => {
            icmp_checksum = value;
        },
        Err(e)=> println!("Error: {}", e),
    }

    //// ICMPパケットを生成
    let mut icmp_packet:Vec<u8> = Vec::<u8>::new();
    icmp_packet.push(icmp_type);
    icmp_packet.push(icmp_code);
    icmp_packet.push((icmp_checksum >> 8) as u8);
    icmp_packet.push((icmp_checksum & 0xff) as u8);
    icmp_packet.push((identification >> 8) as u8);
    icmp_packet.push((identification & 0xff) as u8);
    icmp_packet.push((icmp_seq >> 8) as u8);
    icmp_packet.push((icmp_seq & 0xff) as u8);
    icmp_packet.append(&mut icmp_data);

    Ok(icmp_packet)
}

pub fn create_icmp_checksum(for_checksum_vec:Vec<u16>)->Result<u16,String>{

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

pub fn send_ipv4_packet(sender:&mut TransportSender,destination_ipv4:Ipv4Addr,ipv4_packet:&[u8])->Result<(),String>{
    let send_packet = Ipv4Packet::new(ipv4_packet)
        .ok_or_else(|| "invalid IPv4 bytes".to_string())?;
    sender.send_to(send_packet, IpAddr::V4(destination_ipv4)).map_err(|e| format!("send failed: {e}"))?;
    Ok(())
}
