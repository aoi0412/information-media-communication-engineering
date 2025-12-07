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
use std::time::{Instant};
use std::net::{Ipv4Addr, IpAddr, UdpSocket, SocketAddrV4};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
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
    let mut ipv4_packet:Vec<u8> = Vec::<u8>::new();

    let tmp_version:u8 = 4;
    let tmp_header_length: u8 = 5;
    let tmp_dscp:u8 = 0;
    let tmp_ecn:u8 = 0;
    let tmp_packet_length:u16 = (header_len + payload.len()) as u16;
    let tmp_df: u8 = 0;
    let tmp_mf: u8 = 0;
    let tmp_frags: u8 = tmp_df << 1 | tmp_mf;
    let mut tmp_fragment_offset: u16 = 0;
    let tmp_ttl: u8 = 64;
    let tmp_protocol_num: u8 = 1; // ICMPプロトコル = 1
    let mut tmp_checksum: u16 = 0;
    let mut checksum_frag1: usize = 0;
    let mut checksum_frag2: usize = 0;
    let tmp_destination: u32 = destination_ipv4.to_bits();
    let tmp_source: u32 = source_ipv4.to_bits();

    ipv4_packet.push((tmp_version << 4) | tmp_header_length);
    ipv4_packet.push((tmp_dscp << 2) | tmp_ecn);
    ipv4_packet.push((tmp_packet_length >> 8) as u8);
    ipv4_packet.push((tmp_packet_length & 0xff) as u8);
    ipv4_packet.push((identification >> 8) as u8);
    ipv4_packet.push((identification & 0xff) as u8);
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
    println!("↓IPv4ヘッダ");
    tmp_checksum = create_checksum(for_checksum_vec)?;
    ipv4_packet[checksum_frag1] = (tmp_checksum >> 8) as u8;
    ipv4_packet[checksum_frag2] = (tmp_checksum & 0xff) as u8;
    println!("送信パケット(IPv4ヘッダ):{:x?}", ipv4_packet);

    ipv4_packet.extend_from_slice(&payload);
    println!("送信パケット(ICMPヘッダ):{:x?}", payload);

    Ok(ipv4_packet)
}

pub fn create_icmp_packet(icmp_type: u8, icmp_code: u8, icmp_data:String, identification:u16, icmp_seq:u16) -> Result<Vec<u8>,String>{
    let mut for_checksum_vec = Vec::<u16>::new();
    let icmp_checksum: u16 = 0;
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

    println!("↓ICMPヘッダ");
    let icmp_checksum = create_checksum(for_checksum_vec)?;

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

pub fn create_checksum(for_checksum_vec:Vec<u16>)->Result<u16,String>{
    let mut sum:u32 = 0;
    for_checksum_vec.into_iter().for_each(|tmp|{
        sum = sum + tmp as u32;
    });
    while (sum >> 16) != 0 {
        // 下位16桁を取り出して、取り出した16桁に上位16桁を足す
        sum = (sum & 0xffff) + (sum >> 16);
    }
    println!("チェックサム生成 → 0x{:x}\n", !(sum as u16));

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

pub fn check_checksum(for_checksum_vec:Vec<u8>)->Result<(), String>{
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
    println!("チェックサム検証 → 0x{:x}\n",sum);
    if sum == 0xffff{
        Ok(())
    }else{
        
        println!("チェックサムの検証に失敗しました");
        Ok(())
    }
}

pub fn analysis_packet(ipv4_packet_data: Ipv4Packet<'_>, start: Instant, identification: u16) -> Result<bool, String> {
    // IPv4パケットヘッダの「total_length」が実際のものと相違があるため、get_payload()を使わずに手動でペイロードを取り出す
    let receive_bytes = ipv4_packet_data.packet();
    let receive_header_length = (ipv4_packet_data.get_header_length() * 4) as usize;
    let receive_ipv4_header = &receive_bytes[..receive_header_length];
    let receive_payload = &receive_bytes[receive_header_length..];
    let receive_icmp_identification = u16::from_be_bytes([receive_payload[4],receive_payload[5]]);
    if receive_icmp_identification != identification {
        return Ok(false)
    }
    println!("受信パケット(IPv4ヘッダ):{:x?}", receive_ipv4_header);
    println!("受信パケット(ICMPヘッダ):{:x?}", receive_payload);
    

    // 応急処置としてパケット長を上書き
    let mut fixed_ipv4_header = receive_ipv4_header.to_vec();
    let [b2, b3] = (32u16).to_be_bytes();
    if fixed_ipv4_header.len() >= 4 {
        fixed_ipv4_header[2] = b2;
        fixed_ipv4_header[3] = b3;
    }
    println!("受信パケットを修正(パケット長→32):{:x?}\n", fixed_ipv4_header);

    println!("↓IPv4ヘッダ");
    // check_checksum(fixed_ipv4_header)?;
    check_checksum(receive_ipv4_header.to_vec())?;
    println!("↓ICMPヘッダ");
    check_checksum(receive_payload.to_vec())?;
    
    
    // ICMPパケットのみに絞る
    let receive_protocol = ipv4_packet_data.get_next_level_protocol();
    if receive_protocol == IpNextHeaderProtocols::Icmp {
        // Echo Replyかつ識別子が送信パケットと同じもののみに絞る
        let receive_icmp_type = receive_payload[0];
        
        // ICMPパケットの各項目を取得
        let receive_icmp_code = receive_payload[1];
        let receive_icmp_checksum = u16::from_be_bytes([receive_payload[2],receive_payload[3]]);
        let receive_icmp_seq = u16::from_be_bytes([receive_payload[6],receive_payload[7]]);
        let receive_icmp_data = unsafe { std::str::from_utf8_unchecked(&receive_payload[8..]) };

        // RRTを計測
        let duration = start.elapsed();
        let ms = duration.as_secs_f64() * 1000.0;

        if receive_icmp_type == 0 {
            
            // 結果を出力
            println!("↓ICMP Echo Reply");
            print!("type = {} ", receive_icmp_type);
            print!("code = {} ", receive_icmp_code);
            print!("checksum =  {:#06x} ", receive_icmp_checksum);
            print!("identification = {:#06x} ", receive_icmp_identification);
            print!("seq = {} ", receive_icmp_seq);
            println!("data = {} ", receive_icmp_data);
            println!("time = {:.4} ms", ms);
            println!("");
            return Ok(true);
        } else {
            // 結果を出力
            println!("↓ Failed ICMP Echo Reply");
            print!("type = {} ", receive_icmp_type);
            print!("code = {} ", receive_icmp_code);
            print!("checksum =  {:#06x} ", receive_icmp_checksum);
            print!("identification = {:#06x} ", receive_icmp_identification);
            print!("seq = {} ", receive_icmp_seq);
            println!("data = {} ", receive_icmp_data);
            println!("time = {:.4} ms", ms);
            println!("");
        };
    };
    Ok(false)
}
