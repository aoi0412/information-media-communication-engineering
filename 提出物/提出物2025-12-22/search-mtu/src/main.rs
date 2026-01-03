// --- 自作ライブラリ ---
use utility;
use utility::check_checksum;

// --- 外部ライブラリ ---
use rand::{rng, Rng};

// --- 標準ライブラリ ---
use std::time::{Duration, Instant};
use std::net::Ipv4Addr;
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};


#[derive(Debug)]
struct SentPacketInfo {
    identification: u16,
    icmp_seq: u16,
    current_max_mtu:u16,
    start_instant: Instant,
    rtt: Duration,
}

#[derive(Debug)]
struct IthernetPacketInfo {
    dest_mac_addr: [u8;6],
    source_mac_addr: [u8;6],
    ether_type: u16,
}

impl IthernetPacketInfo {
    fn new() -> Self {
        Self {
            dest_mac_addr: [0; 6],
            source_mac_addr: [0; 6],
            ether_type: 0,
        }
    }
}

#[derive(Debug)]
struct Ipv4PacketInfo {
    version: u8,
    header_length: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags_fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
}

impl Ipv4PacketInfo {
    fn new() -> Self {
        Self {
            version: 0,
            header_length: 0,
            tos: 0,
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            ttl: 0,
            protocol: 0,
            header_checksum: 0,
            source_ip: Ipv4Addr::new(0, 0, 0, 0),
            dest_ip: Ipv4Addr::new(0, 0, 0, 0),
        }
    }
}

#[derive(Debug)]
struct IcmpPacketInfo {
    icmp_type: u8,
    icmp_code: u8,
    icmp_checksum: u16,
    icmp_payload: Vec<u8>,
}

impl IcmpPacketInfo {
    fn new() -> Self {
        Self {
            icmp_type: 0,
            icmp_code: 0,
            icmp_checksum: 0,
            icmp_payload: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct PacketFormattedData {
    ithernet_info: IthernetPacketInfo,
    ipv4_info: Ipv4PacketInfo,
    icmp_info: IcmpPacketInfo,
    ithernet_bytes: Vec<u8>,
    ipv4_bytes: Vec<u8>,
    icmp_bytes: Vec<u8>,
}


fn main()-> Result<(), Box<dyn std::error::Error>> {

    // 引数にIPv4アドレスを受け取る＆IPv4形式かどうかを確認
    let arg_ipaddress = std::env::args().nth(1).expect("no send ip address given");

    let destination_ipv4 = utility::check_ipv4_address(&arg_ipaddress)?;
    let ttl:u8 = 64;
    let first_mtu:u16 = 1500;


    let sent_packets = Arc::new(Mutex::new(Vec::<SentPacketInfo>::new()));
    let current_max_mtu = Arc::new(Mutex::new(first_mtu));
    let pcap_ready = Arc::new(AtomicBool::new(false));
    let is_received = Arc::new(AtomicBool::new(false));
    let is_finished = Arc::new(AtomicBool::new(false));
    println!("search mtu to {}, {} hops max, first mtu is {} ", destination_ipv4, ttl, first_mtu);
    println!("");

    // ---パケット受信スレッドを作成---
    let pcap_ready_clone = Arc::clone(&pcap_ready);
    let sent_packets_clone = Arc::clone(&sent_packets);
    let is_received_clone = Arc::clone(&is_received);
    let is_finished_clone = Arc::clone(&is_finished);
    let current_max_mtu_clone = Arc::clone(&current_max_mtu);
    thread::spawn(move || {
        let devices = libpcap::findalldevs();
        let device_index = devices.iter().position(|r| r == "en0").unwrap();
        let snaplen = 65535;
        let promisc = true;
        let timeout_ms = 10;
        let mut Packet = match libpcap::open_live(devices[device_index].as_str(), snaplen, promisc, timeout_ms) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("pcap openlive failed: {}", e);
                pcap_ready_clone.store(true, Ordering::SeqCst);
                return;
            }
        };
        // 受信側が pcap を開いたことを通知
        pcap_ready_clone.store(true, Ordering::SeqCst);

        libpcap::setfilter(&mut Packet,"icmp");
        let mut analyzed_sent_packet = Vec::<SentPacketInfo>::new();
        loop {
            let ret = libpcap::next_ex(&mut Packet);
            if ret == 0 {
                // タイムアウト（pcap の内部タイムアウト）。忙しい待ちを避ける
                thread::sleep(Duration::from_millis(10));
                continue;
            } else if ret < 0 {
                eprintln!("pcap next_ex error: {}", ret);
                libpcap::close(&mut Packet);
                break;
            }
            
            // PacketからVec<u8>に変換
            let received_data = Packet.data;
            let received_len = Packet.head.len;
            let mut received_bytes:Vec<u8> = Vec::new();
            if received_len == 0 {
                continue;
            }
            unsafe {
                for i in 0..received_len{
                    let a = received_data.offset(i as isize);
                    received_bytes.push(*a);
                }
            }
            // received_bytes: 受信パケットのバイト列, packets: 送信済みパケット情報のリスト
            let packet_formatted_data = analyze_packet_info(&received_bytes).unwrap();
            let sent_packets = sent_packets_clone.lock().unwrap();
            for packet_info in sent_packets.iter() {
                // packet_formatted_dataがanalyzed_received_packetに同じものがない場合のみ処理を行う
                if analyzed_sent_packet.iter().any(|x| x.identification == packet_info.identification && x.icmp_seq == packet_info.icmp_seq) {
                    continue;
                }
                // ICMPパケットかどうかを確認
                if packet_formatted_data.ipv4_info.protocol != 1 {
                    continue;
                }
                // IPv4とICMPのチェックサム
                check_checksum(packet_formatted_data.ipv4_bytes.clone()).unwrap();
                check_checksum(packet_formatted_data.icmp_bytes.clone()).unwrap();
                if packet_formatted_data.icmp_info.icmp_type == 3 && packet_formatted_data.icmp_info.icmp_code == 4{
                    // ICMPペイロードから元の送信パケットの識別子とシーケンス番号を取得
                    let analyzed_icmp_payload = analyze_err_icmp_payload(&packet_formatted_data.icmp_bytes).unwrap();
                    let received_icmp_packet = analyzed_icmp_payload.received_icmp_packet;
                    let sended_ipv4_packet = analyzed_icmp_payload.sended_ipv4_packet;
                    let sended_icmp_packet = analyzed_icmp_payload.sended_icmp_packet;
                    if sended_icmp_packet.icmp_payload.len() < 4 {
                        println!("");
                        continue;
                    }
                    let sended_icmp_identification = u16::from_be_bytes([sended_icmp_packet.icmp_payload[0], sended_icmp_packet.icmp_payload[1]]);
                    let sended_icmp_seq = u16::from_be_bytes([sended_icmp_packet.icmp_payload[2], sended_icmp_packet.icmp_payload[3]]);
                    
                    // 識別子のチェック
                    if sended_ipv4_packet.identification != packet_info.identification && sended_icmp_identification != packet_info.identification {
                        continue;
                    }
                    // シーケンス番号のチェック
                    if sended_icmp_seq != packet_info.icmp_seq {
                        continue;
                    }

                    // RRT計測(ICMPペイロードから送信時刻を取得)
                    let rtt = packet_info.start_instant.elapsed();
                    let dest_ip = packet_formatted_data.ipv4_info.source_ip;
                    println!("fragment needed! {:.3} ms {} ", rtt.as_secs_f64() * 1000.0, dest_ip);

                    // Next-Hop MTUを取得
                    let next_hop_mtu: u16 = u16::from_be_bytes([received_icmp_packet.icmp_payload[2], received_icmp_packet.icmp_payload[3]]);
                    let mtu_updated = {
                        let mut current_max = current_max_mtu_clone.lock().unwrap();
                        if next_hop_mtu < *current_max {
                            let old_max = *current_max;
                            *current_max = next_hop_mtu;
                            Some((old_max, next_hop_mtu))
                        } else {
                            None
                        }
                    };
                    
                    if let Some((old_max, new_max)) = mtu_updated {
                        println!("| max mtu updated! :{} -> {}", old_max, new_max);
                        println!("");
                    }



                    

                    // is_receivedをtrueに
                    is_received_clone.store(true, Ordering::SeqCst);
                    let current_max = current_max_mtu_clone.lock().unwrap();
                    analyzed_sent_packet.push(SentPacketInfo{
                        identification: packet_info.identification,
                        icmp_seq: packet_info.icmp_seq,
                        current_max_mtu: *current_max,
                        start_instant: packet_info.start_instant,
                        rtt: packet_info.rtt,
                    });
                } else if packet_formatted_data.icmp_info.icmp_type == 0 {
                    // 識別子のチェック
                    let received_icmp_identification = u16::from_be_bytes([packet_formatted_data.icmp_info.icmp_payload[0], packet_formatted_data.icmp_info.icmp_payload[1]]);
                    if received_icmp_identification != packet_info.identification {
                        continue;
                    }
                    // シーケンス番号のチェック
                    let received_icmp_seq = u16::from_be_bytes([packet_formatted_data.icmp_info.icmp_payload[2], packet_formatted_data.icmp_info.icmp_payload[3]]);
                    if received_icmp_seq != packet_info.icmp_seq {
                        continue;
                    }


                    // RRT計測(ICMPペイロードから送信時刻を取得)
                    let rtt = packet_info.start_instant.elapsed();
                    let dest_ip = packet_formatted_data.ipv4_info.source_ip;

                    println!("Echo Reply!! {:.3} ms {} ", rtt.as_secs_f64() * 1000.0, dest_ip);
                    println!("");
                    // 最終的なMTUを出力する
                    print!("final mtu: {}", first_mtu);
                    for data in analyzed_sent_packet.iter() {
                        print!(" -> {}",data.current_max_mtu);
                    }
                    println!("");
                
                    // 正常終了を通知
                    is_received_clone.store(true, Ordering::SeqCst);
                    is_finished_clone.store(true, Ordering::SeqCst);
                }
                
            }
        }
    });

    // ---------------------------

    // 受信スレッドが pcap を開くまで待機してから送信を開始
    while !pcap_ready.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(5));
    }
    
    // ---パケット送信---
    let mut icmp_count:u16 = 0;
    let sent_packets_clone2 = Arc::clone(&sent_packets);
    let current_max_mtu_clone = Arc::clone(&current_max_mtu);
    
    loop {
        if is_finished.load(Ordering::SeqCst) {
            break;
        }
        let payload = {
            let mtu = *current_max_mtu_clone.lock().unwrap();
            create_payload_from_mtu_num(mtu).unwrap()
        };
        match send_packet(icmp_count, destination_ipv4, ttl, payload) {
            Ok((identification, icmp_seq, start_instant)) => {
                
                // 送信済みパケットを受信側スレッドで監視できるようにする
                {
                    let mut sent_packets = sent_packets_clone2.lock().unwrap();
                    sent_packets.push(SentPacketInfo {
                        identification: identification,
                        icmp_seq: icmp_seq,
                        current_max_mtu: 0,
                        start_instant: start_instant,
                        rtt: Duration::from_secs(0),
                    });
                }


                icmp_count += 1;

                // is_receivedがtrueになるまで待機し、trueだったらfalseにして次のパケットを送信する
                while !is_received.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1000));
                }
                is_received.store(false, Ordering::SeqCst);
            }
            Err(err) => {
                println!("Error sending packet: {}", err);
                thread::sleep(Duration::from_millis(1000));
            }
        }
        
    }
    // ---------------------------
    Ok(())
}

// 指定されたMTUからaを並べたStringを生成する
fn create_payload_from_mtu_num(mtu:u16)-> Result<String, String>{
    let payload_size = mtu - 20 - 20;
    let mut payload:String = "".to_string();
    for _ in 0..payload_size {
        payload = payload + "a";
    }
    Ok(payload)
}

// Result<(identification, icmp_seq, ttl, start_duration), String>
fn send_packet(icmp_seq:u16, destination_ipv4: Ipv4Addr, ttl: u8, payload: String)-> Result<(u16, u16, Instant),String>{

    // パケットのヘッダーに使う識別子を生成
    let identification: u16 = rng().random();

    // Echo Requestパケットを生成
    let start_instant = Instant::now();
    let mut tmp_create_icmp_packet_args:utility::CreateIcmpPacketArgs = utility::CreateIcmpPacketArgs::default();
    tmp_create_icmp_packet_args.icmp_type = 8;
    tmp_create_icmp_packet_args.icmp_code = 0;
    tmp_create_icmp_packet_args.icmp_seq = icmp_seq;
    tmp_create_icmp_packet_args.identification = identification;
    tmp_create_icmp_packet_args.payload = payload;
    let icmp_echo_request_packet = utility::create_icmp_packet(tmp_create_icmp_packet_args)?;

    // 宛先IPから送り元IPを取得（UDPを使用）
    let source_ipv4 = utility::get_source_ipv4(destination_ipv4)?;

    // IPv4パケットを生成
    let mut tmp_create_ipv4_packet_args:utility::CreateIpv4PacketArgs = utility::CreateIpv4PacketArgs::default();
    tmp_create_ipv4_packet_args.destination_ipv4 = destination_ipv4;
    tmp_create_ipv4_packet_args.source_ipv4 = source_ipv4;
    tmp_create_ipv4_packet_args.identification = identification;
    tmp_create_ipv4_packet_args.ttl = ttl;
    tmp_create_ipv4_packet_args.payload = icmp_echo_request_packet;
    tmp_create_ipv4_packet_args.df = true;
    let ipv4_packet = utility::create_ipv4_packet(tmp_create_ipv4_packet_args)?;

    // socketを作成
    let (mut sender, _) = utility::create_socket()?;

    // パケットを送信
    utility::send_ipv4_packet(&mut sender, destination_ipv4, &ipv4_packet)?;

    return Ok((identification, icmp_seq, start_instant));
}

// libpcapから受け取った生パケットの中身を解析
fn analyze_packet_info(packet_data: &[u8]) -> Result<PacketFormattedData,String>{
    let mut ithernet_packet_info:IthernetPacketInfo = IthernetPacketInfo::new();
    let mut ipv4_packet_info:Ipv4PacketInfo = Ipv4PacketInfo::new();
    let mut icmp_packet_info:IcmpPacketInfo = IcmpPacketInfo::new();
    ithernet_packet_info.dest_mac_addr = [packet_data[0],packet_data[1],packet_data[2],packet_data[3],packet_data[4],packet_data[5]];
    ithernet_packet_info.source_mac_addr = [packet_data[6],packet_data[7],packet_data[8],packet_data[9],packet_data[10],packet_data[11]];
    ithernet_packet_info.ether_type = u16::from_be_bytes([packet_data[12],packet_data[13]]);
    ipv4_packet_info.version = (packet_data[14] & 0xF0) >> 4;
    ipv4_packet_info.header_length = packet_data[14] & 0x0F;
    ipv4_packet_info.tos = packet_data[15];
    ipv4_packet_info.total_length = u16::from_be_bytes([packet_data[16],packet_data[17]]);
    ipv4_packet_info.identification = u16::from_be_bytes([packet_data[18],packet_data[19]]);
    ipv4_packet_info.flags_fragment_offset = u16::from_be_bytes([packet_data[20],packet_data[21]]);
    ipv4_packet_info.ttl = packet_data[22];
    ipv4_packet_info.protocol = packet_data[23];
    ipv4_packet_info.header_checksum = u16::from_be_bytes([packet_data[24],packet_data[25]]);
    ipv4_packet_info.source_ip = Ipv4Addr::new(packet_data[26],packet_data[27],packet_data[28],packet_data[29]);
    ipv4_packet_info.dest_ip = Ipv4Addr::new(packet_data[30],packet_data[31],packet_data[32],packet_data[33]);

    icmp_packet_info.icmp_type = packet_data[34];
    icmp_packet_info.icmp_code = packet_data[35];
    icmp_packet_info.icmp_checksum = u16::from_be_bytes([packet_data[36],packet_data[37]]);
    icmp_packet_info.icmp_payload = packet_data[38..].to_vec();
    Ok(PacketFormattedData {
        ithernet_info: ithernet_packet_info,
        ipv4_info: ipv4_packet_info,
        icmp_info: icmp_packet_info,
        ithernet_bytes: packet_data[0..14].to_vec(),
        ipv4_bytes: packet_data[14..34].to_vec(),
        icmp_bytes: packet_data[34..].to_vec(),
    })
}


// ICMPエラーメッセージのペイロードから元の送信パケット(IPv4ヘッダ + ICMPヘッダ)を解析
struct AnalyzedIcmpPayload {
    received_icmp_packet: IcmpPacketInfo,
    sended_ipv4_packet: Ipv4PacketInfo,
    sended_icmp_packet: IcmpPacketInfo,
}
fn analyze_err_icmp_payload(payload: &[u8]) -> Result<AnalyzedIcmpPayload, String> {
    // [0..7]: ICMPエラーメッセージのヘッダ, [8..]: 元の送信パケット(IPv4ヘッダ + ICMPヘッダ)
    let original_ip_header_length = ((payload[8] & 0x0F) * 4) as usize;
    let original_icmp_packet = &payload[8 + original_ip_header_length..];
    let sended_ipv4_packet = Ipv4PacketInfo {
        version: (payload[8] & 0xF0) >> 4,
        header_length: payload[8] & 0x0F,
        tos: payload[9],
        total_length: u16::from_be_bytes([payload[10],payload[11]]),
        identification: u16::from_be_bytes([payload[12],payload[13]]),
        flags_fragment_offset: u16::from_be_bytes([payload[14],payload[15]]),
        ttl: payload[16],
        protocol: payload[17],
        header_checksum: u16::from_be_bytes([payload[18],payload[19]]),
        source_ip: Ipv4Addr::new(payload[20],payload[21],payload[22],payload[23]),
        dest_ip: Ipv4Addr::new(payload[24],payload[25],payload[26],payload[27]),
    };

    let sended_icmp_packet = IcmpPacketInfo {
        icmp_type: original_icmp_packet[0],
        icmp_code: original_icmp_packet[1],
        icmp_checksum: u16::from_be_bytes([original_icmp_packet[2],original_icmp_packet[3]]),
        icmp_payload: original_icmp_packet[4..].to_vec(),
    };
    let received_icmp_packet = IcmpPacketInfo {
        icmp_type: payload[0],
        icmp_code: payload[1],
        icmp_checksum: u16::from_be_bytes([payload[2],payload[3]]),
        icmp_payload: payload[4..].to_vec(),
    };
    Ok(AnalyzedIcmpPayload {
        received_icmp_packet,
        sended_ipv4_packet,
        sended_icmp_packet,
    })

}