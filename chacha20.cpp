// chacha20_encrypt(key, counter, nonce, plaintext):
//     for j = 0 upto floor(len(plaintext)/64)-1
//         key_stream = chacha20_block(key, counter+j, nonce)
//         block = plaintext[(j*64)..(j*64+63)]
//         encrypted_message +=  block ^ key_stream
//         end
//     if ((len(plaintext) % 64) != 0)
//         j = floor(len(plaintext)/64)
//         key_stream = chacha20_block(key, counter+j, nonce)
//         block = plaintext[(j*64)..len(plaintext)-1]
//         encrypted_message += (block^key_stream)[0..len(plaintext)%64]
//         end
//     return encrypted_message
//     end

// inner_block (state):
//     Qround(state, 0, 4, 8,12)
//     Qround(state, 1, 5, 9,13)
//     Qround(state, 2, 6,10,14)
//     Qround(state, 3, 7,11,15)
//     Qround(state, 0, 5,10,15)
//     Qround(state, 1, 6,11,12)
//     Qround(state, 2, 7, 8,13)
//     Qround(state, 3, 4, 9,14)
//     end

// chacha20_block(key, counter, nonce):
//     state = constants | key | counter | nonce
//     working_state = state
//     for i=1 upto 10
//     inner_block(working_state)
//     end
//     state += working_state
//     return serialize(state)
//     end

#include <iostream>
#include <iomanip>
#include <cstdint>

uint32_t left_rotate(uint32_t value, unsigned int n) {
    // Убираем избыточные сдвиги (n может быть больше 32)
    n %= 32;
    return (value << n) | (value >> (32 - n));
}

void q_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = left_rotate(*d, 16);
    *c += *d; *b ^= *c; *b = left_rotate(*b, 12);
    *a += *b; *d ^= *a; *d = left_rotate(*d, 8);
    *c += *d; *b ^= *c; *b = left_rotate(*b, 7);
}

int main() {
    uint32_t a = 0x11111111, b = 0x01020304, c = 0x9b8d6f43, d = 0x01234567;
    q_round(&a, &b, &c, &d);

    std::cout << "Results after q_round:" << std::endl;
    std::cout << "a: 0x" << std::setw(8) << std::setfill('0') << std::hex << a << std::endl;
    std::cout << "b: 0x" << std::setw(8) << std::setfill('0') << std::hex << b << std::endl;
    std::cout << "c: 0x" << std::setw(8) << std::setfill('0') << std::hex << c << std::endl;
    std::cout << "d: 0x" << std::setw(8) << std::setfill('0') << std::hex << d << std::endl;
    return 0;
}