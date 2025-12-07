use utility::check_checksum;
use std::time::{Instant, Duration};
use rand::{rng, Rng};
use pnet::transport::ipv4_packet_iter;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

fn main()-> Result<(), Box<dyn std::error::Error>> {
    let mode:&str = "simple"; // detail or simple
    // 引数にIPv4アドレスを受け取る＆IPv4形式かどうかを確認
    let ipaddress = std::env::args().nth(1).expect("no send ip address given");
    let destination_ipv4 = utility::check_ipv4_address(&ipaddress)?;


    // pingを実行する回数を指定＆パケット損失のカウント
    let ping_exec_num = 5;
    let mut loss_count = 0;
    let mut rtt_list:Vec<f32> = Vec::new();

    // 以下を指定回数繰り返す
    // 1. パケットの生成
    // 2. パケットの送信
    // 3. パケットの受信
    // 4. パケットの解析
    for icmp_seq in 0..ping_exec_num {
        if mode == "detail"{
            println!("----- パケット生成&送信 -----\n");
        }
        // パケットのヘッダーに使う識別子を生成
        let mut rng = rng();
        let identification: u16 = rng.random();

        if mode == "detail" {
            println!("識別子：{}\n",identification);
        }

        // Echo Requestパケットを生成
        let icmp_echo_request_packet = utility::create_icmp_packet(8,0,String::from("test"),identification,icmp_seq as u16, mode)?;

        // 宛先IPから送り元IPを取得（UDPを使用）
        let source_ipv4 = utility::get_source_ipv4(destination_ipv4)?;

        // IPv4パケットを生成
        let ipv4_packet = utility::create_ipv4_packet(destination_ipv4, source_ipv4, identification, 64, icmp_echo_request_packet, mode)?;

        // socketを作成
        let (mut sender, mut receiver) = utility::create_socket()?;

        // パケットを送信（RTTの計測開始）
        
        let start = Instant::now();
        utility::send_ipv4_packet(&mut sender, destination_ipv4, &ipv4_packet)?;

        if mode == "detail"{
            println!("-----------------------\n");
        }else if mode == "simple" && icmp_seq == 0{
            println!("PING {} ({}): {} data bytes", destination_ipv4, destination_ipv4, ipv4_packet.len())
        }

        // パケットの受信を監視
        if mode == "detail"{
            println!("----- パケット受信 -----\n");
        }
        let mut iter = ipv4_packet_iter(&mut receiver);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut got_reply: bool = false;
        loop {
            match iter.next_with_timeout(Duration::from_millis(100))? {
                Some((ipv4_packet_data, _ipaddr)) => {

                    let (result_analysis, time) = analysis_packet(ipv4_packet_data, start, identification, mode)?;
                    if result_analysis {
                        // パケット損失を加算
                        loss_count = loss_count + 1;
                        got_reply = true;
                        rtt_list.push(time);
                    }
                }
                None => {}
            }
            if Instant::now() >= deadline {
                if !got_reply {
                    if mode == "detail"{
                        println!("------------------- Timeout -------------------");
                        println!("Request timeout for icmp_seq {}", icmp_seq);
                        println!("-------------------------------------------------------");
                    } else if mode == "simple"{
                        println!("Request timeout for icmp_seq {}", icmp_seq);
                    }
                    
                }
                break;
            }
        }
        if mode == "detail"{
            println!("-----------------------\n\n\n");
        }
    }
    
    let loss_rate = ((ping_exec_num - loss_count) as f32) / (ping_exec_num as f32) * 100.0;
    println!("loss_rate:{:.1}%",loss_rate);
    let (min, avg, max, stddev) = utility::calc_stats(&rtt_list)?;
    println!("round-trip min/avg/max/stddev = {:.3}/{:.3}/{:.3}/{:.3} ms",min,avg,max,stddev);
    Ok(())
}

pub fn analysis_packet(ipv4_packet_data: Ipv4Packet<'_>, start: Instant, identification: u16, mode: &str) -> Result<(bool, f32), String> {
    // IPv4パケットヘッダの「total_length」が実際のものと相違があるため、get_payload()を使わずに手動でペイロードを取り出す
    let receive_bytes = ipv4_packet_data.packet();
    let receive_header_length = (ipv4_packet_data.get_header_length() * 4) as usize;
    let receive_ipv4_header = &receive_bytes[..receive_header_length];
    let receive_payload = &receive_bytes[receive_header_length..];
    let receive_icmp_identification = u16::from_be_bytes([receive_payload[4],receive_payload[5]]);
    if receive_icmp_identification != identification {
        return Ok((false, 0.0))
    }

    if mode == "detail"{
        println!("受信パケット(IPv4ヘッダ):{:x?}", receive_ipv4_header);
        println!("受信パケット(ICMPヘッダ):{:x?}", receive_payload);
    }
    

    // 応急処置としてパケット長を上書き
    let mut fixed_ipv4_header = receive_ipv4_header.to_vec();
    let truth_total_length:usize = receive_bytes.len();
    let [b2, b3] = (truth_total_length as u16).to_be_bytes();
    if fixed_ipv4_header.len() >= 4 {
        fixed_ipv4_header[2] = b2;
        fixed_ipv4_header[3] = b3;
    }
    if mode == "detail"{
        println!("受信パケットを修正(パケット長→32):{:x?}\n", fixed_ipv4_header);
    }
    if ipv4_packet_data.get_source().to_string() != "127.0.0.1"{
        let ipv4_sum = check_checksum(fixed_ipv4_header)?;
        // check_checksum(receive_ipv4_header.to_vec())?;
        let icmp_sum = check_checksum(receive_payload.to_vec())?;

        if mode == "detail"{
            println!("↓ICMPヘッダ");
            println!("チェックサム検証 → 0x{:x}\n",icmp_sum);
            println!("↓IPv4ヘッダ");
            println!("チェックサム検証 → 0x{:x}\n",ipv4_sum);

        }
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

        if receive_icmp_type == 0 {
            
            // 結果を出力
            if mode == "detail"{
                println!("↓ICMP Echo Reply");
                print!("type = {} ", receive_icmp_type);
                print!("code = {} ", receive_icmp_code);
                print!("checksum =  {:#06x} ", receive_icmp_checksum);
                print!("identification = {:#06x} ", receive_icmp_identification);
                print!("seq = {} ", receive_icmp_seq);
                println!("data = {} ", receive_icmp_data);
                println!("time = {:.3} ms", ms);
                println!("");
            }else if mode == "simple"{
                println!("{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms", truth_total_length, ipv4_packet_data.get_source(), receive_icmp_seq, ipv4_packet_data.get_ttl(), ms);
            }
            
            return Ok((true, ms as f32));
        } else {
            // 結果を出力
            if mode == "detail"{
                println!("↓ Failed ICMP Echo Reply");
                print!("type = {} ", receive_icmp_type);
                print!("code = {} ", receive_icmp_code);
                print!("checksum =  {:#06x} ", receive_icmp_checksum);
                print!("identification = {:#06x} ", receive_icmp_identification);
                print!("seq = {} ", receive_icmp_seq);
                println!("data = {} ", receive_icmp_data);
                println!("time = {:.3} ms", ms);
                println!("");
            };
        };
    };
    Ok((false,0.0))
}