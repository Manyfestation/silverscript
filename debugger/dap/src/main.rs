use std::io::{BufReader, BufWriter};

use dap::prelude::Server;
use secp256k1::{Keypair, Secp256k1, rand::thread_rng};

mod adapter;
mod launch_config;
mod refs;

use adapter::DapAdapter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--keygen") {
        return keygen();
    }

    let input = BufReader::new(std::io::stdin());
    let output = BufWriter::new(std::io::stdout());
    let mut server = Server::new(input, output);
    let mut adapter = DapAdapter::new();

    loop {
        let req = match server.poll_request() {
            Ok(Some(req)) => req,
            Ok(None) => break,
            Err(err) => return Err(Box::new(err)),
        };

        let result = adapter.handle_request(req);
        if let Err(err) = server.respond(result.response) {
            return Err(Box::new(err));
        }

        for event in result.events {
            if let Err(err) = server.send_event(event) {
                return Err(Box::new(err));
            }
        }

        if result.should_exit {
            break;
        }
    }
    Ok(())
}

fn keygen() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let kp = Keypair::new(&secp, &mut thread_rng());
    let (xonly, _parity) = kp.x_only_public_key();
    let secret_bytes = kp.secret_key().secret_bytes();
    let pubkey_bytes = xonly.serialize();
    let pkh = blake2b_simd::Params::new().hash_length(32).hash(&pubkey_bytes);

    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };

    println!(r#"{{"pubkey":"0x{}","secret_key":"0x{}","pkh":"0x{}"}}"#, hex(&pubkey_bytes), hex(&secret_bytes), hex(pkh.as_bytes()),);
    Ok(())
}
