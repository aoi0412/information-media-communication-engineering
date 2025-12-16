fn main() {
    let devices = libpcap::findalldevs();
    
    let device_index = devices.iter().position(|r| r == "en0").unwrap();
    println!("Find devices {:?},\nUse device: {}",devices,devices[device_index]);

    let mut Packet = libpcap::open(devices[device_index].as_str());

    libpcap::setfilter(&mut Packet,"icmp and host 192.168.3.156");
	
    while let data = libpcap::next_ex(&mut Packet){
        // println!("{:?},{:?}",Packet.data,Packet.head.len);
        println!("PacketData:");
        unsafe {
            for i in 0..Packet.head.len{
                let a = Packet.data.offset(i as isize);
                print!("{:02x} ",*a);
            }
        }
        println!("");
    }

    libpcap::close(&mut Packet);
}