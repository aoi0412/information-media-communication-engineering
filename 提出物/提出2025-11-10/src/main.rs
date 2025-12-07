mod createpacket;
use std::time::{Instant, Duration};
use rand::{rng, Rng};
use pnet::transport::ipv4_packet_iter;



fn main()-> Result<(), Box<dyn std::error::Error>> {
    // 引数にIPv4アドレスを受け取る＆IPv4形式かどうかを確認
    let ipaddress = std::env::args().nth(1).expect("no send ip address given");
    let destination_ipv4 = createpacket::check_ipv4_address(&ipaddress)?;


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
        println!("----- パケット生成&送信 -----\n");
        // パケットのヘッダーに使う識別子を生成
        let mut rng = rng();
        let identification: u16 = rng.random();
        println!("識別子：{}\n",identification);
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
        println!("-----------------------\n");

        // パケットの受信を監視
        println!("----- パケット受信 -----\n");
        let mut iter = ipv4_packet_iter(&mut receiver);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut got_reply: bool = false;
        loop {
            match iter.next_with_timeout(Duration::from_millis(100))? {
                Some((ipv4_packet_data, _ipaddr)) => {

                    let result_analysis = createpacket::analysis_packet(ipv4_packet_data, start, identification)?;
                    if result_analysis {
                        // パケット損失を加算
                        loss_count = loss_count + 1;
                        got_reply = true;
                    }
                }
                None => {}
            }
            if Instant::now() >= deadline {
                if !got_reply {
                    println!("------------------- Timeout -------------------");
                    println!("|Request timeout for icmp_seq {}", icmp_seq);
                    println!("-------------------------------------------------------");
                }
                break;
            }
        }
        println!("-----------------------\n\n\n");
    }
    
    let loss_rate = ((ping_exec_num - loss_count) as f32) / (ping_exec_num as f32) * 100.0;
    println!("loss_rate:{:.1}%",loss_rate);
    Ok(())
}
