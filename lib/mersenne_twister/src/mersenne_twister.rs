/* MT19937 Mersenne Twister RNG library
 *
 * Official Mersenne Twister page:
 * http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

#![crate_name="mersenne_twister"]
#![crate_type="lib"]

extern crate test;

use std::cmp::max;
use std::iter::range_step;


static N: uint = 624;
static M: uint = 397;

pub trait MersenneTwisterSeed {
    fn get_state(&self) -> Vec<u32>;
}

impl<'a> MersenneTwisterSeed for &'a[u32] {
    fn get_state(&self) -> Vec<u32> {
        init_by_vec(*self)
    }
}

impl MersenneTwisterSeed for u32 {
    fn get_state(&self) -> Vec<u32> {
        init_by_vec(&[*self])
    }
}

impl MersenneTwisterSeed for i64 {
    fn get_state(&self) -> Vec<u32> {
        let first: u32 = *self as u32;
        let second: u32 = (*self as u64 >> 32) as u32;
        init_by_vec(&[first, second])
    }
}

pub struct MersenneTwister {
    state: Vec<u32>,
    index: uint
}

impl MersenneTwister {
    pub fn new<S: MersenneTwisterSeed>(init_key: S) -> Self {
        MersenneTwister{state: init_key.get_state(), index: N}
    }

    pub fn rand_u32(&mut self) -> u32 {
        if self.index >= N {
            self.init();
        }
        let mut y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^ (y >> 18)
    }

    pub fn rand_f64(&mut self) -> f64 {
        self.rand_u32() as f64 / 4294967296.0
    }

    #[inline]
    fn init(&mut self) {
        for i in range(0, N) {
            let y = (self.state[i] & 0x80000000)
                    | (self.state[(i + 1) % N] & 0x7fffffff);
            self.state[i] = match y % 2 {
                0 => self.state[(i + M) % N] ^ (y >> 1),
                _ => self.state[(i + M) % N] ^ (y >> 1) ^ 0x9908b0df
            }
        }
        self.index = 0;
    }

    /*
     * Split the RNG by guessing the internal state.
     */
    pub fn split(&mut self) -> Self {
        let state: Vec<u32>  = range(0, N).map(|_| {
            let mut v = self.rand_u32();
            v ^= v >> 18;
            v ^= (v << 15) & 0xefc60000;
            // Recover correct bits step by step
            v = range_step(0u, 32, 7).fold(v, |v, shift| {
                v ^ (((v << 7) & 0x9d2c5680) & (0x3f80 << shift))
            });
            range_step(0u, 32, 11).fold(v, |v, shift| {
                v ^ ((v >> 11) & (0xffe00000 >> shift))
            })
        }).collect();
        MersenneTwister{state: state, index: N}
    }
}

#[inline]
fn init_state(seed: u32) -> Vec<u32> {
    range(0, N as u32).scan(seed, |state, i| {
        let prev = *state;
        *state = 1812433253 * (*state ^ (*state >> 30)) + i + 1;
        Some(prev)
    }).collect()
}

#[inline]
fn init_by_vec(init_key: &[u32]) -> Vec<u32> {
    let mut state = init_state(19650218);
    let len = init_key.len();
    let limit = N - 1;
    for i in range(0, max(N, len)) {
        let idx = i % limit;
        let k_idx = i % len;
        state[idx + 1] = (state[idx + 1]
            ^ ((state[idx] ^ (state[idx] >> 30)) * 1664525))
            + init_key[k_idx] + k_idx as u32;
        if (i + 1) % limit == 0 {
            state[0] = state[limit];
        }
    }
    for i in range(2, N) {
        state[i] = (state[i]
            ^ ((state[i - 1] ^ (state[i - 1] >> 30)) * 1566083941)) - i as u32;
    }
    state[1] = (state[1]
        ^ ((state[N - 1] ^ (state[N - 1] >> 30)) * 1566083941)) - 1;
    state[0] = 0x80000000;
    state
}

/*
 * Tests
 *
 * Link to the test data:
 * http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.out
 */
#[cfg(test)]
mod tests {
    use test::Bencher;

    use super::MersenneTwister;

    #[test]
    fn test_rand_u32() {
        let expected: [u32, ..50] = [
            1067595299, 955945823, 477289528, 4107218783, 4228976476,
            3344332714, 3355579695, 227628506, 810200273, 2591290167,
            2560260675, 3242736208, 646746669, 1479517882, 4245472273,
            1143372638, 3863670494, 3221021970, 1773610557, 1138697238,
            1421897700, 1269916527, 2859934041, 1764463362, 3874892047,
            3965319921, 72549643, 2383988930, 2600218693, 3237492380,
            2792901476, 725331109, 605841842, 271258942, 715137098,
            3297999536, 1322965544, 4229579109, 1395091102, 3735697720,
            2101727825, 3730287744, 2950434330, 1661921839, 2895579582,
            2370511479, 1004092106, 2247096681, 2111242379, 3237345263,
        ];
        let mut rng = MersenneTwister::new(
            [0x123, 0x234, 0x345, 0x456].as_slice());
        for (i, &exp) in expected.iter().enumerate() {
            assert_eq!((i, exp), (i, rng.rand_u32()));
        }
    }

    #[test]
    fn test_rand_f64() {
        let expected: [f64, ..50] = [
            0.76275443, 0.99000644, 0.98670464, 0.10143112, 0.27933125,
            0.69867227, 0.94218740, 0.03427201, 0.78842173, 0.28180608,
            0.92179002, 0.20785655, 0.54534773, 0.69644020, 0.38107718,
            0.23978165, 0.65286910, 0.07514568, 0.22765211, 0.94872929,
            0.74557914, 0.62664415, 0.54708246, 0.90959343, 0.42043116,
            0.86334511, 0.19189126, 0.14718544, 0.70259889, 0.63426346,
            0.77408121, 0.04531601, 0.04605807, 0.88595519, 0.69398270,
            0.05377184, 0.61711170, 0.05565708, 0.10133577, 0.41500776,
            0.91810699, 0.22320679, 0.23353705, 0.92871862, 0.98897234,
            0.19786706, 0.80558809, 0.06961067, 0.55840445, 0.90479405,
        ];
        let mut rng = MersenneTwister::new(
            [0x123, 0x234, 0x345, 0x456].as_slice());
        // For the test data we use 1000 values should be skipped
        for _ in range(0u, 1000) {
            rng.rand_f64();
        }
        for (i, &exp) in expected.iter().enumerate() {
            assert_eq!((i, true), (i, rng.rand_f64() - exp < 0.00000001f64));
        }
    }

    #[bench]
    fn bench_rand_u32(b: &mut Bencher) {
        let mut rng = MersenneTwister::new(
            [0x123, 0x234, 0x345, 0x456].as_slice());
        b.iter(|| rng.rand_u32());
    }

    #[bench]
    fn bench_new(b: &mut Bencher) {
        let init_key = [0x123, 0x234, 0x345, 0x456];
        let init_key_slice = init_key.as_slice();
        b.iter(|| MersenneTwister::new(init_key_slice));
    }
}
