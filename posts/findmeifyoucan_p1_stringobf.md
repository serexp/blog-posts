Blog post
# Find me if you can: countering static and dynamic artifacts
## Part one: strings

*We will (1) show why strings leak, (2) survey three obfuscation tactics, (3) build a C++17 header-only library that encrypts strings at compile-time and wipes them at run-time.*


**TL;DR: we hide strings by encrypting them at compile-time with a constexpr XOR + LCG, then wipe the plaintext from the stack when it goes out of scope. Full source is a single C++17 header. [Code available here](https://github.com/serexp/blog-posts/blob/main/src/xorlcg_stringobf.hpp)**

Anti-viruses and Endpoint Detection and Response products rely on static analysis to analyze potentially malicious apps statically, i.e: without running them. This is different from dynamic analysis, where executables will be run and analyzed live as they execute.

One of the main ways to know if a sample is “more or less malicious” is the strings it uses. These can be analyzed statically, proving to be extremely useful. It is much easier and cheaper to analyze a program at rest rather than dynamically.

To demonstrate this, let’s compile a minimal Windows executable and then inspect its strings with the GNU `strings` utility:

```
╭─ 🌙 serexp at 🌙 host in 🌙 ~/blog in
╰─λ cat sample.c
#include <stdio.h>

int main(void){
  return puts("wowzers!");
}
╭─ 🌙 serexp at 🌙 host in 🌙 ~/blog in
╰─λ x86_64-w64-mingw32-gcc sample.c -flto -O2 -s -o sample.exe # flto, O2, s used to strip and optimize for size to minimize strings.
```
With this said, let's check the content! I will annotate all strings to give you a better reading experience.
```
╭─ 🌙 serexp at 🌙 host in 🌙 ~/blog in
╰─λ strings sample.exe
!This program cannot be run in DOS mode.
.text # Section name
`.data
.rdata
@.pdata
@.xdata
@.bss
.idata
.CRT
.tls
.reloc # Final section name
wowzers! # <---- OUR STRING!
Argument domain error (DOMAIN) # start C runtime error msgs
Argument singularity (SIGN)
Overflow range error (OVERFLOW)
Partial loss of significance (PLOSS)
Total loss of significance (TLOSS)
The result is too small to be represented (UNDERFLOW)
Unknown error
_matherr(): %s in %s(%g, %g)  (retval=%g)
Mingw-w64 runtime failure:
Address %p has no image-section
  VirtualQuery failed for %d bytes at address %p
  VirtualProtect failed with code 0x%x
  Unknown pseudo relocation protocol version %d.
  Unknown pseudo relocation bit size %d.
%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p. # finish C runtime error msgs
GCC: (GNU) 13-win32 # Compiler's signature
DeleteCriticalSection # start IAT/imports
EnterCriticalSection
GetLastError
InitializeCriticalSection
LeaveCriticalSection
SetUnhandledExceptionFilter
Sleep
TlsGetValue
VirtualProtect
VirtualQuery
__C_specific_handler
__getmainargs
__initenv
__iob_func
__set_app_type
__setusermatherr
_amsg_exit
_cexit
_commode
_fmode
_initterm
_onexit
abort
calloc
exit
fprintf
free
fwrite
malloc
memcpy
puts
signal
strlen
strncmp
vfprintf
KERNEL32.dll
msvcrt.dll # end IAT/imports
```

The first strings we can see are the number of *sections*. For a beginner, we can explain that a section is a way for the compiler to divide your code into multiple parts, for optimization, security or convenience reasons. Each of these individual sections has given permissions. That is, your `.text` section almost always contains your executable code. For security reasons, it is read-only at runtime on all modern OSes. This means that trying to modify your own code dynamically WILL fail. This is known as **Read-Execute (RX)**, while `.data` is **Read-Write (RW)**, allowing the compiler to put our globals (and strings) on it.

The *C runtime*, also known as the *CRT* is a set of libraries and function that are offered by your compiler. These significantly ease our lives as programmers. The CRT includes helpers like `strlen`, `printf`, `malloc`, etc. I will write a blog post on it when I feel better mentally, though all you need to know is that, while these functions are helpful, they are used by virtually all C programs. Therefore, it would be a waste of size and performance to embed them in every C program. For this reason, they are imported at run-time (albeit automatically). On Windows, this makes them part of your program's **Import Addresses Table/IAT**. Your IAT is populated at run-time with pointers to all external functions you import. Though, this deserves its own blog post, sorry, I want to do it well :').

With this said, the most important we can notice is our string, `wowzers` being detected! A reverse engineer can infer a lot from strings. Here, one may infer that our program is benign and awesome, though if our application was more sensitive maybe they could discover hard-coded API keys, secret end-points, etc.

To counter this, we can obfuscate our strings. There are two, maybe three ways to do it:

### 1. Static encryption
Perhaps the most obvious: encrypting strings with a script and replace all occurrences of it with the encrypted value, and decrypting them manually before use.
This requires to:
- Obfuscate the string statically using a script (i.e: python script you use from the CLI),
- replacing uses of the string by the encrypted value,
- Making sure to decrypt it with the right inverse algorithm at run-time,
- Optionally wiping it from memory, though adversaries that use this are often not advanced enough to care about memory artifacts (though, don't let this discourage you: wiping memory is a finishing touch; don’t feel inadequate if you skip it on your first tinkering weekend :] ).

In my opinion, doing this is the most bothersome and perhaps ironically the hardest way to do it:
- It require a lot of manual work and/or cryptographic knowledge,
- You will need to either re-write cryptographic routines or link them at runtime. If linked at runtime, your program will simply not work if the libraries aren't supplied by the OS. If you link statically, it will make your program very large (maybe 5-10MB larger)
- If you don't use the same library for encryption and decryption, nothing guarantees their outputs will be the same. [Example](https://github.com/Ginurx/chacha20-c/issues/3).


### Compiler-based obfuscation
Some compilers compile your code to a language called an Intermediary Representation (IR) and perform actions on it based on your request. Two great advantages are:
- You can create arbitrary plugins to perform actions on this IR code,
- The IR code is universal. Using LLVM to compile Rust will generate IR in the same way that compiling C would. They more or less compile to common instructions and the same IR.

This one is very satisfying to create, you will need to use a compiler that supports plugins like clang/LLVM and create a plugin that edits the IR directly instead of messing with the source-code. This is a portable option (work on Rust, C, C++ code...) and sounds perfect, until you learn that you need to compile a lot of stuff from scratch that takes literal hours (LLVM) and create a plugin for an API that very often introduces breaking changes. It is not impossible, though! Some have done it, some continue to, but it requires a lot of time, which many of us don't have (unfortunately!).


### 3. Compile-time obfuscation
This method is the best in my eyes.
You will compile strings at compile-time and decrypt them at run-time. One way to perform this is in C is using C constant expressions (constexprs) (introduced in C23) or C++ constexprs.
There is very little support for C constexprs on mainstream compiles on mainstream distros and they are more limited than C++ constexprs, so we will use the latter for the purpose of this article.

Since C lacks true compile-time function evaluation like C++'s constexpr, we’ll use C++ for the obfuscation layer—even if your main project is in C. You can link the obfuscated strings into C code seamlessly

One limitation is that whatever you encrypt needs to be evaluated at compile-time. This means that you cannot use algorithms like AES, chacha20 or the likes. <sup>[1]</sup>
I will have the pleasure of demonstrating an implementation for this :).


# Architecture of a compile-time string obfuscation library
For its architecture, we want something that can be moderately easy to write and is somewhat hard to bruteforce and "easy" to implement.

Initially, this section was about 6000 characters, after which I realized that I was significantly out of scope. For now, I will only give the constants we use and how we will use them. I will explain everything (the why and how) in another post, as I believe it deserves its own.

We will use a simple XOR cipher. XOR instructions take one CPU cycle on [almost all CPUs](https://www.agner.org/optimize/instruction_tables.pdf ) and are widely-used for simple encryption. Decrypting xor'd data is also easy, its inverse function is itself.

Our pseudo-random number generator is a LCG defined as **x<sub>n</sub> = (ax<sub>n−1</sub>+c) mod m**.

For our constants, I chose\
**m = 2^64**\
**a = 6364136223846793005**\
**c = 1442695040888963407**

Rationale:
1. Maximal period.
    For (1) to attain the full period **m**, the three famous conditions (Knuth, L’Ecuyer) must hold:
    - c and m are coprime (true: c is odd, m is a power of two)
    - a−1 is divisible by every prime that divides m (only prime is 2, and a−1 = 6364…3004 is divisible by 4)
    - if m is a multiple of 4 then a−1 must be a multiple of 4 (also true).
     Hence period = m = 2^64.
2. Good spectral scores.
    The two constants are taken from L’Ecuyer, “Tables of linear congruential generators of different sizes and good lattice structure”, 1999. They give the smallest figure of merit ≥ 0.73 for all dimensions up to 32. Way more than good enough for obfuscation while keeping the arithmetic 64-bit-wide and compile-time friendly.
3. Can be optimized easily. `m` is a power of two so the compiler turns “mod m” into a mask (or even nothing when the upper half of a 128-bit product is just ignored). No costly division instruction is emitted.

To sum it up, we will use a 64-bit LCG to give us pseudo-random numbers that we will then use to xor our strings with at compile-time. Constants used for the LCG were given and the rationale behind them was also given. We will use C++ constant expressions to do all of this.

With this done, let's get to the implementation.


## Implementation
```C++
namespace lcg {
    using state_type = std::uint64_t;
    constexpr state_type k_mult = 6364136223846793005ULL;
    constexpr state_type k_incr = 1442695040888963407ULL;
    constexpr state_type prng(state_type s) noexcept { return s * k_mult + k_incr; }

    constexpr state_type rotr(state_type x, unsigned n) noexcept {
        return (x >> n) | (x << (64 - n));
    }

    template <std::size_t N>
    constexpr state_type hash_seed(const char (&str)[N], state_type salt = 0xcbf29ce484222325) noexcept {
        state_type h = salt;
        for (std::size_t i = 0; i < N; ++i) {
            h ^= static_cast<unsigned char>(str[i]);
            h *= 0x100000001b3ULL;
        }
        return (h << 1) | 1;          // force odd
    }
} // namespace lcg
template <std::size_t N>
struct encrypted {
    std::uint64_t seed;
    unsigned char data[N];
};

template <std::size_t N>
constexpr auto encrypt(const char (&plain)[N], std::uint64_t seed) noexcept { // [5] for cryptographic attacks on this
    encrypted<N> out{};
    out.seed = seed;
    std::uint64_t stream = seed;
    for (std::size_t i = 0; i < N; ++i) {
        out.data[i] = static_cast<unsigned char>(plain[i]) ^
                      static_cast<unsigned char>(stream);
        stream = lcg::prng(stream);
    }
    return out;
}

template <std::size_t N, typename Buf>
constexpr void decrypt(const encrypted<N>& cipher, Buf& buf) noexcept {
    std::uint64_t stream = cipher.seed;
    for (std::size_t i = 0; i < N; ++i) {
        buf[i] = cipher.data[i] ^ static_cast<unsigned char>(stream);
        stream = lcg::prng(stream);
    }
}

// ---------- per-project salt ----------
namespace {
    constexpr std::uint64_t k_lcg_salt = 0x1234567890abcdef; // CHANGE ME
}

// ---------- macro ----------
/* WARNING:
* This is OBFUSCATION
* NOT CRYPTOGRAPHY!
* Do not use this to hide very sensitive secrets, your secret key is embedded in the source code!
*/
#define OBF(str) \
    ([]() { \
        static constexpr encrypted<sizeof(str)> cipher = \
            encrypt(str, lcg::hash_seed(str, k_lcg_salt)); \
        std::array<char, sizeof(str)> buf{}; \
        decrypt(cipher, buf); \
        return buf; }())

int main() {
    auto msg = OBF("wowzers!");
    std::cout << msg.data() << '\n';   // prints: wowzers!
}
```
This code works perfectly, your strings are wrapped inside OBF() and can be used as such. They are lazily decrypted (i.e only decrypted when the code for it is encountered).
Though, this version does leave a memory artifact, the string is left in memory after decryption. *Strictly speaking, nothing guarantees it will be left in memory. In the same fashion, nothing guarantees it will be wiped after going out of scope. It will probably stay on stack for a while until that memory is needed. It is better to assume the worst :)*.

To counter this, we can use **destructors**, one of the few useful things in modern C++. They are methods we can specify that perform actions whn an object goes out of scope.
We will define one that does its best[4] to wipe our string, character by character, once it goes out of scope, as such:
```C++
namespace detail {
    inline void secure_zero(void* p, std::size_t n) noexcept {
        volatile unsigned char* v = static_cast<volatile unsigned char*>(p); // [4]
        while (n--) *v++ = 0; // zero the string
    }
} // namespace detail

template <std::size_t N>
struct wipe_on_exit {
    char buf[N];
    constexpr wipe_on_exit() noexcept { buf[0] = '\0'; } // leave trivially default-constructible
    wipe_on_exit(const wipe_on_exit&)            = delete;
    wipe_on_exit& operator=(const wipe_on_exit&) = delete;
    // Move constructor and assignment are defined below, so no need to delete them here

    ~wipe_on_exit() noexcept { detail::secure_zero(buf, N); }
    wipe_on_exit(wipe_on_exit&& rhs) noexcept {
        std::memcpy(buf, rhs.buf, N);
        detail::secure_zero(rhs.buf, N);   // source wiped
    }
    wipe_on_exit& operator=(wipe_on_exit&& rhs) noexcept {
        detail::secure_zero(buf, N); // junk data (if any) gone first
        std::memcpy(buf, rhs.buf, N); // then copy
        detail::secure_zero(rhs.buf, N); // then wipe
        return *this;
    }
    char* data() noexcept { return buf; }
    const char* data() const noexcept { return buf; }
    static constexpr std::size_t size() noexcept { return N; }
};
```
We also need to update our macro to support it:
```C++
#define OBF(str) \
    ([]() { \
        static constexpr encrypted<sizeof(str)> cipher = \
            encrypt(str, lcg::hash_seed(str, k_lcg_salt)); \
        wipe_on_exit<sizeof(str)> w{}; \ /* wipe it :') */
        decrypt(cipher, w.buf); \
        return w; }())   // NRVO / move-elision gives you the object
```

We can use our OBF string as previously defined:
```C++
int main() {
    auto msg = OBF("wowzers!");
    std::cout << msg.data() << '\n';
}
```
**Our library is now complete.** Strings are obfuscated at compile-time, decrypted at run-time lazily, wiped from memory once out of scope. However, please read the remark appended at the end[2].

Analysis reveals:
```
╭─ 🌙 serexp at 🌙 host in 🌙 ~/blog in
╰─λ x86_64-w64-mingw32-g++ sample.cpp -flto -O2 -s -o sample.exe -Wall -Wextra -Wpedantic -static
╭─ 🌙 serexp at 🌙 host in 🌙 ~/blog in
╰─λ wine sample.exe
wowzers!
╭─ 🌙 serexp at 🌙 host in 🌙 ~/blog in
╰─λ strings sample.exe | grep -iF wowzers
[no output]
```

Final remarks
---
[1] You can re-code ChaCha20 to be usable in a constexpr. Nobody has done it (as far as I know), but it is entirely possible.
[2] I should perhaps state explicitly that the scheme we use is obfuscation, **not cryptography**. This is not cryptographically safe and should not be considered as such. It prevents most attacks at rest but is not cryptography. Our constants (a, c, m) are hard-coded in the binary and could be pulled out by a determined analyst and used to brute-force our strings offline.
[3] Do NOT reuse salts. This could lead to a dictionary attack
[4] `volatile unsigned char*` does not guarantee wiping across all compilers (MSVC sometimes removes it anyway). Look into RtlSecureZeroMemory / explicit_bzero / memset_s as alternatives.
[5] Because the LCG key-stream is data-independent, the decryption loop is already constant-time, so we don’t risk key-dependent branches or cache timing leaks.

It is entirely possible to create a variant of this that doesn't rely on the C++ runtime! Please do so, actually! :')

It was a lot of fun to work on this. Overall, it took maybe two weeks of reading about pseudo-random number generators (PRNGs) and a few days of thinking of the architecture of this in throughout details.

Further reading:
https://www.johndcook.com/blog/2023/09/24/mersenne-primes-are-unsafe/
L'ecuyer on prime numbers in MCLGs: https://www.ams.org/journals/mcom/1999-68-225/S0025-5718-99-00996-5/S0025-5718-99-00996-5.pdf
Lehmer's PRNGs: https://www.cs.odu.edu/~cmo/classes/old/cs475sp05/leemisText/07_c21.pdf

Further mischief
---
Next post will be about the math behind this :)
