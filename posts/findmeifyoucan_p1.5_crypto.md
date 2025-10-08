This post is a continuation of the first part: `Find me if you can: string obfuscation` and gives a rationale for the choice of algorithms used.

Initially, I wanted to use a MLCG initialized with a Mersenne Prime. After much research for this article I learned that Mersenne Primes are not suitable at all for cryptographically-safe operations, according to John Cook. Check [2](https://www.johndcook.com/blog/2023/09/24/victorian-public-key-cryptography/) and [3](https://www.johndcook.com/blog/2023/09/24/mersenne-primes-are-unsafe/) for more info :). Technically, it is not important if it is suitable for cryptography or not. Our goal is obfuscation, not encryption. Any prime that has a long enough period would've been good enough.
The prime I had in mind (2^31-1) did not satisfy this:

- Period too small, 2^31 - 1 ≈ 2.1 × 10^9.  A 3 GB file already contains that many bytes; the generator could theoretically repeat within a single compilation unit.

- Not a safe prime. A prime *p* is “safe” for crypto only when p = 2q + 1 with *q* prime. 2^31 - 1 - 1 = 2(2^30 − 1). 2^30 − 1 factors into many small primes -> the multiplicative group has tiny sub-groups -> Pohlig–Hellman reduces the discrete-log problem to trivial pieces. **That is irrelevant for obfuscation**, but it shows the prime was never intended for security.

- Low-order bits are terrible. An LCG’s k-th least significant bit has period 2ᵏ. With 32 bits the lowest bit period is 2; the second is 4, etc. Obfuscation that only needs a few bits (e.g. XOR with characters) will cycle visibly.

... We  will ditch the Mersenne prime altogether. Better safe than sorry, no?

A 64-bit LCG with power-of-two modulus fixes all of the above:
- period 2^64 (> 10^19) – impossible to exhaust at compile time. Every bit, including the lowest, has a full period of 2^64.
- multiplication and addition compile to two instructions; no division.
- constants are the best-known spectral-grade values (read this excellent paper by [L’Ecuyer, 1999](https://www.ams.org/journals/mcom/1999-68-225/S0025-5718-99-00996-5/S0025-5718-99-00996-5.pdf)).


We will use a Linear Congruential Generator (LCG) with a 64-bit prime. They are widely used in simple cryptographic implementations.

As for how the encryption works, we will use a simple XOR cipher. XOR instructions take one CPU cycle on [almost all CPUs](https://www.agner.org/optimize/instruction_tables.pdf) and are widely-used for encryption. Decrypting xor'd data is also easy, the inverse of the xor function is itself.

The most widely-known pseudorandom number generators are MLCGs. We will therefore start there: a multiplicative linear congruential generator (MLCG) is defined by a recurrence of the form: **xn = ax<sub>n−1</sub> mod m** where `m` and `a` are integers called the modulus and the multiplier, respectively, and **x<sub>n</sub> ∈ Z<sub>m</sub> = {0, . . . , m − 1}** is the state at step `n`. To obtain a sequence of “random numbers” in the interval **[0, 1)**, one can define the output at step n as **u<sub>n</sub> = x<sub>n</sub>/m**.

MLCGs are built on top of Linear Congruential Generators, LCGs. An LCG is defined by a recurrence of the form:
m – modulus (the size of the state space)
a – multiplier (sometimes written g in older papers)
c – additive constant (a.k.a. increment)

If c ≠ 0 the recurrence **x<sub>n</sub> = (ax<sub>n−1</sub>+c) mod m** is called a LCG. Otherwise, c is null, so it is a MLCG (**xn = (ax<sub>n−1</sub>+0) mod m** obviously simplifies to **xn = ax<sub>n−1</sub> mod m**).

Though this could be out of scope for this post (which should really just be a paper), I would like to explain all architectural choices, so I will justify why a LCG was chosen instead of a MLCG:

MLCGs are attractive when you want m to be a prime (e.g. the famous 2**31-1) because choosing `a` to be a primitive root modulo `m` gives the maximal period `m−1` even though c is zero.
They are, however, a strict subset of LCGs and come with two downsides:
- You cannot start from seed = 0 (it would stick at 0)
- The least-significant k bits still have a period at most 2^k, so the lowest bit is always the worst.

For compile-time obfuscation we do not need a prime modulus, we do not want the short period, and we do want every bit to cycle through the full 2^64 states, since only LCGs offer the full period of our primes..
Using the full LCG with c ≠ 0 and m = 2^64 is therefore the simpler, faster and statistically better choice.


For the purpose of our library, we have chosen:
For our constants, I chose\
**m = 2^64**\
**a = 6364136223846793005**\
**c = 1442695040888963407**

Rationale:
1. Maximal period.
    For (1) to attain the full period m the three famous conditions (Knuth, L’Ecuyer) must hold:
    - c and m are coprime (true: c is odd, m is a power of two)
    - a−1 is divisible by every prime that divides m (only prime is 2, and a−1 = 6364…3004 is divisible by 4)
    - if m is a multiple of 4 then a−1 must be a multiple of 4 (also true).
     Hence period = m = 2^64.
2. Good spectral scores.
    The two constants are taken from L’Ecuyer, “Tables of linear congruential generators of different sizes and good lattice structure”, 1999. They give the smallest figure of merit ≥ 0.73 for all dimensions up to 32. Way more than good enough for obfuscation while keeping the arithmetic 64-bit-wide and compile-time friendly.
3. Can be optimized easily. `m` is a power of two so the compiler turns “mod m” into a mask (or even nothing when the upper half of a 128-bit product is simply ignored). No costly division instruction is emitted.

To sum it up, we will use a 64-bit LCG to give us pseudo-random numbers that we will then use to xor our strings at compile-time. Constants used for the LCG were given and the rationale behind them was also given.
