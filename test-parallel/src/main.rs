use std::thread;
use std::sync::mpsc;
use std::time::Duration;
use std::collections::HashMap;

fn main(){
    // --snip--
    loop {
        let (tx, rx) = mpsc::channel();

        let tx1 = mpsc::Sender::clone(&tx);
        thread::spawn(move || {
            let vals = vec![
                (String::from("hi"),1),
                (String::from("from"),1),
                (String::from("the"),3),
                (String::from("thread"),4),
            ];
            thread::sleep(Duration::from_secs(1));
            for val in vals {
                tx1.send(val).unwrap();
                thread::sleep(Duration::from_secs(2));
            }
        });

        thread::spawn(move || {
            // 君のためにもっとメッセージを(more messages for you)
            let vals = vec![
                (String::from("more"),5),
                (String::from("messages"),6),
                (String::from("for"),7),
                (String::from("you"),8),
            ];

            for val in vals {
                tx.send(val).unwrap();
                thread::sleep(Duration::from_secs(2));
            }
        });


        for received in &rx {
            let (tmp_1, tmp_2) = received;
            println!("{}:{}", tmp_2, tmp_1);
            
            
        }
    }

    // --snip--

}

