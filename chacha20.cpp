// >>>>> ПСЕВДОКОД

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

// <<<<< ПСЕВДОКОД

#include <iostream>
#include <iomanip>
#include <cstdint>

void test_q_round();
void test_chacha20_block();

const uint32_t _CONSTANTS[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

uint32_t left_rotate(uint32_t value, size_t n) {
    n %= 32;
    return (value << n) | (value >> (32 - n));
}

void q_round(uint32_t* state, size_t a, size_t b, size_t c, size_t d) {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = left_rotate(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = left_rotate(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = left_rotate(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = left_rotate(state[b], 7);
}

void inner_block(uint32_t* state) {
    q_round(state, 0, 4, 8, 12);
    q_round(state, 1, 5, 9, 13);
    q_round(state, 2, 6, 10, 14);
    q_round(state, 3, 7, 11, 15);

    q_round(state, 0, 5, 10, 15);
    q_round(state, 1, 6, 11, 12);
    q_round(state, 2, 7, 8, 13);
    q_round(state, 3, 4, 9, 14);
}

void chacha20_block(const uint32_t* key, uint32_t counter, const uint32_t* nonce, uint32_t* output) {
    uint32_t state_array[16];
    for (int i = 0; i < 4; i++) {
        state_array[i] = _CONSTANTS[i];
    }
    for (int i = 4; i < 12; i++) {
        state_array[i] = key[i-4];
    }
    state_array[12] = counter;
    for (int i = 13; i < 16; i++) {
        state_array[i] = nonce[i-13];
    }

    uint32_t working_state[16];
    for (int i = 0; i < 16; i++) {
        working_state[i] = state_array[i];
        output[i] = state_array[i];
    }

    for (int c = 0; c < 10; c++) {
        inner_block(working_state);
    }

    for (int i = 0; i < 16; i++) {
        output[i] += working_state[i];
    }
}

void serialize(const uint32_t* state_array, uint8_t* output) {
    for (int i = 0; i < 16; ++i) {
        output[i * 4]     = (state_array[i] & 0x000000FF);
        output[i * 4 + 1] = (state_array[i] & 0x0000FF00) >> 8;
        output[i * 4 + 2] = (state_array[i] & 0x00FF0000) >> 16;
        output[i * 4 + 3] = (state_array[i] & 0xFF000000) >> 24;
    }
}

void bytes_to_uint32_array(const uint8_t* data, uint32_t* output, size_t length) {
    // Преобразуем каждые 4 байта в один uint32_t с учетом little-endian порядка
    for (size_t i = 0; i < length / 4; i++) {
        output[i] = data[i * 4] | (data[i * 4 + 1] << 8) | (data[i * 4 + 2] << 16) | (data[i * 4 + 3] << 24);
    }
}

uint8_t* chacha20_encrypt(const uint8_t* key_bytes, uint32_t counter, const uint8_t* nonce_bytes, const uint8_t* plaintext, size_t len) {
    
    uint32_t key[8];
    uint32_t nonce[3];

    bytes_to_uint32_array(key_bytes, key, 32);
    bytes_to_uint32_array(nonce_bytes, nonce, 12);
    
    uint8_t* ciphertext = new uint8_t[len];
    for (int j = 0; j < floor(len/64); ++j) {
        uint32_t block_output[16];
        uint8_t keystream[64];
        chacha20_block(key, counter+j, nonce, block_output);
        serialize(block_output, keystream);

        const uint8_t* block = plaintext + j * 64;
        for (size_t i = 0; i < 64; ++i) {
            ciphertext[i+j*64] = block[i] ^ keystream[i];
        }
    }

    if (len % 64 != 0) {
        uint32_t block_output[16];
        uint8_t keystream[64];
        chacha20_block(key, counter + (len / 64), nonce, block_output);
        serialize(block_output, keystream);
        const uint8_t* block = plaintext + (len / 64) * 64;
        for (size_t i = 0; i < len % 64; i++) {
            ciphertext[i + (len / 64) * 64] = block[i] ^ keystream[i];
        }
    }

    return ciphertext;
}

int main() {

    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    uint32_t counter = 1;

    uint8_t plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };

    size_t plaintext_len = sizeof(plaintext) / sizeof(plaintext[0]);

    uint8_t* ciphertext = chacha20_encrypt(key, counter, nonce, plaintext, plaintext_len);

    std::cout << ">>>>>>> Ciphertext: >>>>>>>\n\n";
    for (size_t i = 0; i < plaintext_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
    std::cout << std::endl;

    // Освобождение памяти
    delete[] ciphertext;

    return 0;
}

void test_q_round() {
    uint32_t state[16] = {
        0x879531e0,  0xc5ecf37d,  0x516461b1,  0xc9a62f8a,
       0x44c20ef3,  0x3390af7f,  0xd9fc690b,  0x2a5f714c,
       0x53372767,  0xb00a5631,  0x974c541a,  0x359e9963,
       0x5c971061,  0x3d631689,  0x2098d9d6,  0x91dbd320
    };

    q_round(state, 2, 7, 8, 13);
    
    std::cout << std::endl << " block after QROUND:" << std::endl;
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << state[i] << " ";
        if ((i + 1) % 4 == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << std::endl << std::endl;
}

void test_chacha20_block() {
    uint32_t key[8] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
    };
    uint32_t nonce[3] = {0x09000000, 0x4a000000, 0x00000000};
    uint32_t counter = 1;
    uint32_t output[16];

    chacha20_block(key, counter, nonce, output);

    std::cout << "ChaCha state at the end of the ChaCha20 operation:" << std::endl;
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << output[i] << " ";
        if ((i + 1) % 4 == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;
}

