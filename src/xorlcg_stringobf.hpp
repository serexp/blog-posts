#ifndef XORLCG_STRINGOBF_H
#define XORLCG_STRINGOBF_H

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <array>
#include <utility>
#include <algorithm>
#include <cstring>

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

namespace detail {
    // portable explicit_bzero
    inline void secure_zero(void* p, std::size_t n) noexcept {
        volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
        while (n--) *v++ = 0;
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
        detail::secure_zero(buf, N);
        std::memcpy(buf, rhs.buf, N);
        detail::secure_zero(rhs.buf, N);
        return *this;
    }
    char* data() noexcept { return buf; }
    const char* data() const noexcept { return buf; }
    static constexpr std::size_t size() noexcept { return N; }
};

template <std::size_t N>
struct encrypted {
    std::uint64_t seed;
    unsigned char data[N];
};

template <std::size_t N>
constexpr auto encrypt(const char (&plain)[N], std::uint64_t seed) noexcept {
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
#define OBF(str) \
    ([]() { \
        static constexpr encrypted<sizeof(str)> cipher = \
            encrypt(str, lcg::hash_seed(str, k_lcg_salt)); \
        wipe_on_exit<sizeof(str)> w{}; \
        decrypt(cipher, w.buf); \
        return w; }())   // NRVO / move-elision gives you the object

/*
int main() {
    {
        auto msg = OBF("wowzers!");
        std::cout << msg.data() << '\n';   // prints: wowzers!
    }
}
*/
#endif // XORLCG_STRINGOBF_H