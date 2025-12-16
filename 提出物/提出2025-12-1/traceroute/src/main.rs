use utility;
use std::time::{Instant, Duration};
use rand::{rng, Rng};
use pnet::transport::ipv4_packet_iter;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use utility::check_checksum;
use rayon::prelude::*;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::net::Ipv4Addr;
use std::thread;



fn main()-> Result<(), Box<dyn std::error::Error>> {

    // 引数にIPv4アドレスを受け取る＆IPv4形式かどうかを確認
    let arg_ipaddress = std::env::args().nth(1).expect("no send ip address given");

    let destination_ipv4 = utility::check_ipv4_address(&arg_ipaddress)?;
    let mut ttl:u8 = 1;
    let mut icmp_seq:u16 = 0;
    
    let mut is_received_reply: bool = false;
    let (tx, rx) = mpsc::channel::<(i32, i32, String)>();
    let response_timeout = Duration::from_secs(3);

    println!("traceroute to {} ({}), 64 hops max", destination_ipv4, destination_ipv4);
    // 以下を指定回数繰り返す
    // 1. パケットの生成
    // 2. パケットの送信
    // 3. パケットの受信
    // 4. パケットの解析
    loop {
        // パケット送信の並列処理を3回行う
        (0..3)
        .into_par_iter()
        .for_each(|_| {
            let tmp_tx: mpsc::Sender<(i32, i32, String)> = mpsc::Sender::clone(&tx);
            
            thread::spawn(move || {
                
                match send_and_receive_packet(icmp_seq, destination_ipv4, ttl, "test".to_string()) {
                    Ok((icmp_type, hop_num, result_string)) => {
                        if icmp_type == 11 || icmp_type == 0 {
                            tmp_tx.send((icmp_type, hop_num, result_string)).unwrap();
                        } else {
                            tmp_tx.send((icmp_type, hop_num, "* ".to_string()));
                        };
                    }
                    Err(err) => {
                        let _ = tmp_tx.send((99, ttl as i32, err));
                    }
                }
            });
        });

        ttl += 1;
        icmp_seq += 1;

        for _ in 0..3 {
            match rx.recv_timeout(response_timeout) {
                Ok((icmp_type, received_hop_num, result_string)) => {
                    println!("{}  {}", received_hop_num, result_string);
                    if icmp_type == 0 {is_received_reply = true;}
                }
                Err(RecvTimeoutError::Timeout) => {
                    println!("{}  * (timeout)", ttl);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    eprintln!("channel closed, exiting");
                    return Ok(());
                }
            }
        }
        if is_received_reply {break Ok(());}
    }
}


// Result<(icmp_type, hop_num, result_string), String>
fn send_and_receive_packet(icmp_seq:u16, destination_ipv4: Ipv4Addr, ttl: u8, payload: String)-> Result<(i32 ,i32, String),String>{

    let mode = "simple".to_string();
    // パケットのヘッダーに使う識別子を生成
    let identification: u16 = rng().random();

    // Echo Requestパケットを生成
    let icmp_echo_request_packet = utility::create_icmp_packet(8,0,payload,identification,icmp_seq, &mode)?;

    // 宛先IPから送り元IPを取得（UDPを使用）
    let source_ipv4 = utility::get_source_ipv4(destination_ipv4)?;

    // IPv4パケットを生成
    let ipv4_packet = utility::create_ipv4_packet(destination_ipv4, source_ipv4, identification, ttl, icmp_echo_request_packet, &mode)?;

    // socketを作成
    let (mut sender, mut receiver) = utility::create_socket()?;

    // パケットを送信（RTTの計測開始）
    let start = Instant::now();
    utility::send_ipv4_packet(&mut sender, destination_ipv4, &ipv4_packet)?;

    // パケットの受信を監視
    let mut iter = ipv4_packet_iter(&mut receiver);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match iter.next_with_timeout(Duration::from_millis(100)).map_err(|e| e.to_string())? {
            Some((ipv4_packet_data, _ipaddr)) => {
                // IPv4パケットヘッダの「total_length」が実際のものと相違があるため、get_payload()を使わずに手動でペイロードを取り出す
                let receive_bytes = ipv4_packet_data.packet();
                let receive_header_length = (ipv4_packet_data.get_header_length() * 4) as usize;
                let receive_source_ipv4 = ipv4_packet_data.get_source();
                let receive_ipv4_header = &receive_bytes[..receive_header_length];
                let receive_payload = &receive_bytes[receive_header_length..];
                let receive_icmp_identification = u16::from_be_bytes([receive_payload[4],receive_payload[5]]);
                // if receive_icmp_identification != identification {
                //     continue;
                // }
                
                // 応急処置としてパケット長を上書き
                let mut fixed_ipv4_header = receive_ipv4_header.to_vec();
                let truth_total_length:usize = receive_bytes.len();
                let [b2, b3] = (truth_total_length as u16).to_be_bytes();
                if fixed_ipv4_header.len() >= 4 {
                    fixed_ipv4_header[2] = b2;
                    fixed_ipv4_header[3] = b3;
                }
                if ipv4_packet_data.get_source().to_string() != "127.0.0.1"{
                    let ipv4_sum = check_checksum(fixed_ipv4_header)?;
                    // check_checksum(receive_ipv4_header.to_vec())?;
                    let icmp_sum = check_checksum(receive_payload.to_vec())?;
                }
                
                
                
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
                    
                    let result_string = vec![receive_source_ipv4.to_string(),"  ".to_string(),format!("{ms:.3}").to_string()," ms".to_string()].join("");
                    return Ok((receive_icmp_type as i32, ttl as i32, result_string));
                };
            }
            None => {}
        }
        if Instant::now() >= deadline {
            return Ok((99, ttl as i32, "*".to_string()));
        }
    }
}
