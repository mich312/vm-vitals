//! vitals — know how your servers are doing.
//!
//! Early scaffold. The design lives in `SPEC.md`; the module layout it grows
//! into is: `config`, `collect/{host,docker,endpoint,tls}`, `store`, `eval`,
//! `notify`, `heartbeat`, `web`. Implementation starts at milestone M0
//! (host + container collectors + a JSON status endpoint on loopback).

fn main() {
    println!("vitals — scaffold. See SPEC.md and README.md; building at M0.");
}
