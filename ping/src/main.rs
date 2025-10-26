mod createpacket;
use std::time::{Instant, Duration};
use pnet::transport::ipv4_packet_iter;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use rand::{rng, Rng};



fn main()-> Result<(), Box<dyn std::error::Error>> {
    // 引数にIPv4アドレスを受け取る＆IPv4形式かどうかを確認
    let ipaddress = std::env::args().nth(1).expect("no send ip address given");
    let destination_ipv4 = createpacket::check_ipv4_address(&ipaddress)?;

    // パケットのヘッダーに使う識別子を生成
    let mut rng = rng();
    let identification: u16 = rng.random();

    // pingを実行する回数を指定＆パケット損失のカウント
    let ping_exec_num = 5;
    let mut loss_count = 0;

    // 以下を指定回数繰り返す
    // 1. パケットの生成
    // 2. パケットの送信
    // 3. パケットの受信
    // 4. パケットの解析
    for icmp_seq in 0..ping_exec_num {
        // Echo Requestパケットを生成
        let icmp_echo_request_packet = createpacket::create_icmp_packet(8,0,String::from("test"),identification,icmp_seq as u16)?;

        // 宛先IPから送り元IPを取得（UDPを使用）
        let source_ipv4 = createpacket::get_source_ipv4(destination_ipv4)?;

        // pnetクレートを使ってIPv4パケットを生成
        let ipv4_packet = createpacket::create_ipv4_packet(destination_ipv4, source_ipv4, identification, icmp_echo_request_packet)?;

        // socketを作成
        let (mut sender, mut receiver) = createpacket::create_socket()?;

        // パケットを送信（RTTの計測開始）
        let start = Instant::now();
        createpacket::send_ipv4_packet(&mut sender, destination_ipv4, &ipv4_packet)?;

        // パケットの受信を監視
        let mut iter = ipv4_packet_iter(&mut receiver);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut got_reply: bool = false;
        loop {
            match iter.next_with_timeout(Duration::from_millis(100))? {
                Some((ipv4_packet_data, _ipaddr)) => {
                    // IPv4パケットヘッダの「total_length」が実際のものと相違があるため、get_payload()を使わずに手動でペイロードを取り出す
                    let receive_bytes = ipv4_packet_data.packet();
                    let receive_header_length = (ipv4_packet_data.get_header_length() * 4) as usize;
                    let receive_payload = &receive_bytes[receive_header_length..];
                    
                    // ICMPパケットのみに絞る
                    let receive_protocol = ipv4_packet_data.get_next_level_protocol();
                    if receive_protocol == IpNextHeaderProtocols::Icmp {

                        // Echo Replyかつ識別子が送信パケットと同じもののみに絞る
                        let receive_icmp_type = receive_payload[0];
                        let receive_icmp_identification = u16::from_be_bytes([receive_payload[4],receive_payload[5]]);
                        if receive_icmp_type == 0 && receive_icmp_identification == identification {

                            // ICMPパケットの各項目を取得
                            let receive_icmp_code = receive_payload[1];
                            let receive_icmp_checksum = u16::from_be_bytes([receive_payload[2],receive_payload[3]]);
                            let receive_icmp_seq = u16::from_be_bytes([receive_payload[6],receive_payload[7]]);
                            let receive_icmp_data = unsafe { std::str::from_utf8_unchecked(&receive_payload[8..]) };

                            // RRTを計測
                            let duration = start.elapsed();
                            let ms = duration.as_secs_f64() * 1000.0;
                            
                            // 結果を出力
                            println!("------------------- ICMP Echo Reply -------------------");
                            println!("icmp_bytes = {:?}", receive_payload);
                            print!("type = {} ", receive_icmp_type);
                            print!("code = {} ", receive_icmp_code);
                            print!("checksum =  {:#06x} ", receive_icmp_checksum);
                            print!("identification = {:#06x} ", receive_icmp_identification);
                            print!("seq = {} ", receive_icmp_seq);
                            println!("data = {} ", receive_icmp_data);
                            println!("time = {:.4} ms", ms);
                            println!("-------------------------------------------------------");

                            // パケット損失を加算
                            loss_count = loss_count + 1;
                            got_reply = true;
                        }
                        
                    }
                }
                None => {}
            }
            if Instant::now() >= deadline {
                if !got_reply {
                    println!("Request timeout for icmp_seq {}", icmp_seq);
                }
                break;
            }
        }
    }
    
    let loss_rate = ((ping_exec_num - loss_count) as f32) / (ping_exec_num as f32) * 100.0;
    println!("loss_rate:{:.1}%",loss_rate);
    Ok(())
}
