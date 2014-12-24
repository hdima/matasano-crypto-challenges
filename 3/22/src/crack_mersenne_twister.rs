/* Crack an MT19937 seed
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate libc;

extern crate mersenne_twister;

use std::rand::random;
use std::io::timer::sleep;
use std::time::duration::Duration;
use std::ptr;
use libc::time_t;

use mersenne_twister::MersenneTwister;

extern {
    fn time(tloc: *const time_t) -> time_t;
}

fn timestamp() -> time_t {
    unsafe {time(ptr::null())}
}

fn get_random_value() -> (u32, time_t) {
    sleep(Duration::seconds(random::<u8>() as i64));
    let seed = timestamp();
    let mut rng = MersenneTwister::new(seed);
    sleep(Duration::seconds(random::<u8>() as i64));
    (rng.rand_u32(), seed)
}

fn guess_seed(val: u32) -> Option<time_t> {
    let mut seed = timestamp();
    for _ in range(0u64, 1000000) {
        let mut rng = MersenneTwister::new(seed);
        if rng.rand_u32() == val {
            return Some(seed);
        }
        seed -= 1;
    }
    return None
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let (val, exp_seed) = get_random_value();
    println!("Random value: {}, Expected seed: {}", val, exp_seed);
    let seed = guess_seed(val);
    match seed {
        Some(s) => println!("Seed found: {}", s),
        None => println!("No seed found")
    }
}
