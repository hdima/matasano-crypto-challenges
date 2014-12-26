/* Clone an MT19937 RNG from its output
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate mersenne_twister;

use std::rand::random;

use mersenne_twister::MersenneTwister;

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let mut rng = MersenneTwister::new(random::<u32>());
    for _ in range(0, random::<u8>()) {
        rng.rand_u32();
    }
    let mut rng_clone = rng.split();
    for i in range(0u64, 1000000) {
        assert_eq!((i, rng.rand_u32()), (i, rng_clone.rand_u32()));
    }
    println!("Cloned OK");
}
