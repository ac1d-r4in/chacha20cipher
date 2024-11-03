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

const uint32_t _CONSTANTS[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

uint32_t left_rotate(uint32_t value, unsigned int n) {
    // Убираем избыточные сдвиги (n может быть больше 32)
    n %= 32;
    return (value << n) | (value >> (32 - n));
}

void q_round(uint32_t* state, int a, int b, int c, int d) {
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

void serialize(const uint32_t* state_array, uint8_t* output) {
    for (int i = 0; i < 16; ++i) {
        // Копируем каждое 32-битное слово в выходной массив в формате little-endian
        output[i * 4]     = (state_array[i] & 0x000000FF); // Младший байт
        output[i * 4 + 1] = (state_array[i] & 0x0000FF00) >> 8; // Второй байт
        output[i * 4 + 2] = (state_array[i] & 0x00FF0000) >> 16; // Третий байт
        output[i * 4 + 3] = (state_array[i] & 0xFF000000) >> 24; // Старший байт
    }
}

void chacha20_block(uint32_t* key, uint32_t counter, uint32_t* nonce, uint8_t* output) {
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
    }

    for (int c = 0; c < 10; c++) {
        inner_block(working_state);
    }

    for (int i = 0; i < 16; i++) {
        state_array[i] += working_state[i];
    }

    // uint8_t result[64];
    serialize(state_array, output);
}

uint8_t* chacha20_encrypt(uint32_t* key, uint32_t counter, uint32_t* nonce, uint8_t* plaintext) {
    int length = sizeof(plaintext);
    uint8_t* ciphertext = new uint8_t[length];
    for (int j = 0; j < floor(length/64); j++) {
        uint8_t keystream[64];
        chacha20_block(key, counter+j, nonce, keystream);

        const uint8_t* block = plaintext + j * 64; // Адрес текущего блока
        for (size_t i = 0; i < 64; ++i) {
            ciphertext[i+j*64] = block[i] ^ keystream[i]; // XOR с шифровым потоком
        }
    }
    return ciphertext;
}

int main() {
    // uint32_t a = 0x11111111, b = 0x01020304, c = 0x9b8d6f43, d = 0x01234567;
    // q_round(&a, &b, &c, &d);

    // std::cout << "Results after q_round:" << std::endl;
    // std::cout << "a: 0x" << std::setw(8) << std::setfill('0') << std::hex << a << std::endl;
    // std::cout << "b: 0x" << std::setw(8) << std::setfill('0') << std::hex << b << std::endl;
    // std::cout << "c: 0x" << std::setw(8) << std::setfill('0') << std::hex << c << std::endl;
    // std::cout << "d: 0x" << std::setw(8) << std::setfill('0') << std::hex << d << std::endl;
    return 0;
}