/* MT19937 Mersenne Twister RNG
 *
 * Official Mersenne Twister page:
 * http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate mersenne_twister;

use mersenne_twister::MersenneTwister;

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let mut rng = MersenneTwister::new([0x123, 0x234, 0x345, 0x456].as_slice());
    for i in range(0u, 1000) {
        match i % 5 == 4 {
            false => print!("{:>10} ", rng.rand_u32()),
            true => println!("{:>10}", rng.rand_u32())
        }
    }
    println!("");
    for i in range(0u, 1000) {
        match i % 5 == 4 {
            false => print!("{:>10.8} ", rng.rand_f64()),
            true => println!("{:>10.8}", rng.rand_f64())
        }
    }
}
