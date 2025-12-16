/*
    Copyright (C) 2023 MrSpike63

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, version 3.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#if defined(_WIN64)
    #define WIN32_NO_STATUS
    #include <windows.h>
    #undef WIN32_NO_STATUS
#endif

#include <thread>
#include <cinttypes>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <queue>
#include <chrono>
#include <fstream>
#include <vector>

#include "secure_rand.h"
#include "structures.h"

#include "cpu_curve_math.h"
#include "cpu_keccak.h"
#include "cpu_math.h"


#define OUTPUT_BUFFER_SIZE 10000

#define BLOCK_SIZE 256U
#define THREAD_WORK (1U << 8)



__constant__ CurvePoint thread_offsets[BLOCK_SIZE];
__constant__ CurvePoint addends[THREAD_WORK - 1];
__device__ uint64_t device_memory[2 + OUTPUT_BUFFER_SIZE * 3];

__constant__ uint8_t device_prefix[40];  // prefix nibbles (index 0 = first char)
__constant__ int device_prefix_len;      // length in nibbles (hex chars)

__constant__ uint8_t device_suffix[40];  // suffix nibbles, reversed (index 0 = last char)
__constant__ int device_suffix_len;      // length in nibbles (hex chars)

__constant__ uint32_t device_leading_char_target;  // target nibble for leading char matching

__device__ int count_zero_bytes(uint32_t x) {
    int n = 0;
    n += ((x & 0xFF) == 0);
    n += ((x & 0xFF00) == 0);
    n += ((x & 0xFF0000) == 0);
    n += ((x & 0xFF000000) == 0);
    return n;
}

__device__ int score_zero_bytes(Address a) {
    int n = 0;
    n += count_zero_bytes(a.a);
    n += count_zero_bytes(a.b);
    n += count_zero_bytes(a.c);
    n += count_zero_bytes(a.d);
    n += count_zero_bytes(a.e);
    return n;
}

__device__ int count_letters(uint32_t x) {
    int n = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (x >> (i * 4)) & 0xF;
        n += (nibble >= 0xa && nibble <= 0xf);  // a-f
    }
    return n;
}

__device__ int score_letters(Address a) {
    int n = 0;
    n += count_letters(a.a);
    n += count_letters(a.b);
    n += count_letters(a.c);
    n += count_letters(a.d);
    n += count_letters(a.e);
    return n;
}

__device__ int count_numbers(uint32_t x) {
    int n = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (x >> (i * 4)) & 0xF;
        n += (nibble <= 0x9);  // 0-9
    }
    return n;
}

__device__ int score_numbers(Address a) {
    int n = 0;
    n += count_numbers(a.a);
    n += count_numbers(a.b);
    n += count_numbers(a.c);
    n += count_numbers(a.d);
    n += count_numbers(a.e);
    return n;
}

__device__ int score_leading_zeros(Address a) {
    uint32_t parts[5] = {a.a, a.b, a.c, a.d, a.e};
    int start_nibble = device_prefix_len;  // Skip prefix if present

    int count = 0;
    for (int i = start_nibble; i < 40; i++) {
        int part_idx = i / 8;           // which uint32_t (0=a, 1=b, etc.)
        int nibble_idx = 7 - (i % 8);   // which nibble within uint32_t (high to low)

        uint8_t nibble = (parts[part_idx] >> (nibble_idx * 4)) & 0xF;
        if (nibble == 0) {
            count++;
        } else {
            break;  // stop at first non-zero
        }
    }
    return count;
}

__device__ int score_leading_char(Address a) {
    const uint32_t target = device_leading_char_target;
    uint32_t parts[5] = {a.a, a.b, a.c, a.d, a.e};
    int start_nibble = device_prefix_len;  // Skip prefix if present

    int count = 0;
    for (int i = start_nibble; i < 40; i++) {
        int part_idx = i / 8;           // which uint32_t (0=a, 1=b, etc.)
        int nibble_idx = 7 - (i % 8);   // which nibble within uint32_t (high to low)

        uint8_t nibble = (parts[part_idx] >> (nibble_idx * 4)) & 0xF;
        if (nibble == target) {
            count++;
        } else {
            break;  // stop at first mismatch
        }
    }
    return count;
}

__device__ int score_prefix_match(Address a) {
    if (device_prefix_len == 0) return 0;

    int prefix_score = 0;
    uint32_t parts[5] = {a.a, a.b, a.c, a.d, a.e};

    for (int i = 0; i < device_prefix_len; i++) {
        int part_idx = i / 8;           // which uint32_t (0=a, 1=b, etc.)
        int nibble_idx = 7 - (i % 8);   // which nibble within uint32_t (high to low)

        uint8_t addr_nibble = (parts[part_idx] >> (nibble_idx * 4)) & 0xF;
        if (addr_nibble == device_prefix[i]) {
            prefix_score += 3;  // 3x weight for prefix matches
        } else {
            break;  // stop at first mismatch
        }
    }

    return prefix_score;
}

__device__ int score_suffix_match(Address a) {
    if (device_suffix_len == 0) return 0;

    int suffix_score = 0;
    uint32_t parts[5] = {a.e, a.d, a.c, a.b, a.a};

    for (int i = 0; i < device_suffix_len; i++) {
        int part_idx = i / 8;      // which uint32_t (0=e, 1=d, etc.)
        int nibble_idx = i % 8;    // which nibble within uint32_t

        uint8_t addr_nibble = (parts[part_idx] >> (nibble_idx * 4)) & 0xF;
        if (addr_nibble == device_suffix[i]) {
            suffix_score += 3;  // 3x weight for suffix matches
        } else {
            break;  // stop at first mismatch
        }
    }

    return suffix_score;
}

#ifdef __linux__
    #define atomicMax_ul(a, b) atomicMax((unsigned long long*)(a), (unsigned long long)(b))
    #define atomicAdd_ul(a, b) atomicAdd((unsigned long long*)(a), (unsigned long long)(b))
#else
    #define atomicMax_ul(a, b) atomicMax(a, b)
    #define atomicAdd_ul(a, b) atomicAdd(a, b)
#endif

__device__ void handle_output(int score_method, Address a, uint64_t key, bool inv) {
    int score = 0;
    if (score_method == 0) { score = score_leading_zeros(a); }
    else if (score_method == 1) { score = score_zero_bytes(a); }
    else if (score_method == 2) { score = score_leading_char(a); }
    else if (score_method == 3) { score = score_letters(a); }
    else if (score_method == 4) { score = score_numbers(a); }
    score += score_prefix_match(a);
    score += score_suffix_match(a);

    if (score >= device_memory[1]) {
        atomicMax_ul(&device_memory[1], score);
        if (score >= device_memory[1]) {
            uint32_t idx = atomicAdd_ul(&device_memory[0], 1);
            if (idx < OUTPUT_BUFFER_SIZE) {
                device_memory[2 + idx] = key;
                device_memory[OUTPUT_BUFFER_SIZE + 2 + idx] = score;
                device_memory[OUTPUT_BUFFER_SIZE * 2 + 2 + idx] = inv;
            }
        }
    }
}

__device__ void handle_output2(int score_method, Address a, uint64_t key) {
    int score = 0;
    if (score_method == 0) { score = score_leading_zeros(a); }
    else if (score_method == 1) { score = score_zero_bytes(a); }
    else if (score_method == 2) { score = score_leading_char(a); }
    else if (score_method == 3) { score = score_letters(a); }
    else if (score_method == 4) { score = score_numbers(a); }
    score += score_prefix_match(a);
    score += score_suffix_match(a);

    if (score >= device_memory[1]) {
        atomicMax_ul(&device_memory[1], score);
        if (score >= device_memory[1]) {
            uint32_t idx = atomicAdd_ul(&device_memory[0], 1);
            if (idx < OUTPUT_BUFFER_SIZE) {
                device_memory[2 + idx] = key;
                device_memory[OUTPUT_BUFFER_SIZE + 2 + idx] = score;
            }
        }
    }
}

#include "address.h"
#include "contract_address.h"
#include "contract_address2.h"
#include "contract_address3.h"


int global_max_score = 0;
std::mutex global_max_score_mutex;
uint32_t GRID_SIZE = 1U << 15;

struct Message {
    uint64_t time;

    int status;
    int device_index;
    cudaError_t error;

    double speed;
    int results_count;
    _uint256* results;
    int* scores;
};

std::queue<Message> message_queue;
std::mutex message_queue_mutex;


#define gpu_assert(call) { \
    cudaError_t e = call; \
    if (e != cudaSuccess) { \
        message_queue_mutex.lock(); \
        message_queue.push(Message{milliseconds(), 1, device_index, e}); \
        message_queue_mutex.unlock(); \
        if (thread_offsets_host != 0) { cudaFreeHost(thread_offsets_host); } \
        if (device_memory_host != 0) { cudaFreeHost(device_memory_host); } \
        cudaDeviceReset(); \
        return; \
    } \
}

uint64_t milliseconds() {
    return (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())).count();
}


void host_thread(int device, int device_index, int score_method, int mode, Address origin_address, Address deployer_address, _uint256 bytecode) {
    uint64_t GRID_WORK = ((uint64_t)BLOCK_SIZE * (uint64_t)GRID_SIZE * (uint64_t)THREAD_WORK);

    CurvePoint* block_offsets = 0;
    CurvePoint* offsets = 0;
    CurvePoint* thread_offsets_host = 0;

    uint64_t* device_memory_host = 0;
    uint64_t* max_score_host;
    uint64_t* output_counter_host;
    uint64_t* output_buffer_host;
    uint64_t* output_buffer2_host;
    uint64_t* output_buffer3_host;

    gpu_assert(cudaSetDevice(device));

    gpu_assert(cudaHostAlloc(&device_memory_host, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t), cudaHostAllocDefault))
    output_counter_host = device_memory_host;
    max_score_host = device_memory_host + 1;
    output_buffer_host = max_score_host + 1;
    output_buffer2_host = output_buffer_host + OUTPUT_BUFFER_SIZE;
    output_buffer3_host = output_buffer2_host + OUTPUT_BUFFER_SIZE;

    output_counter_host[0] = 0;
    max_score_host[0] = 2;
    gpu_assert(cudaMemcpyToSymbol(device_memory, device_memory_host, 2 * sizeof(uint64_t)));
    gpu_assert(cudaDeviceSynchronize())


    if (mode == 0 || mode == 1) {
        gpu_assert(cudaMalloc(&block_offsets, GRID_SIZE * sizeof(CurvePoint)))
        gpu_assert(cudaMalloc(&offsets, (uint64_t)GRID_SIZE * BLOCK_SIZE * sizeof(CurvePoint)))
        thread_offsets_host = new CurvePoint[BLOCK_SIZE];
        gpu_assert(cudaHostAlloc(&thread_offsets_host, BLOCK_SIZE * sizeof(CurvePoint), cudaHostAllocWriteCombined))
    }

    _uint256 max_key;
    if (mode == 0 || mode == 1) {
        _uint256 GRID_WORK = cpu_mul_256_mod_p(cpu_mul_256_mod_p(_uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK}, _uint256{0, 0, 0, 0, 0, 0, 0, BLOCK_SIZE}), _uint256{0, 0, 0, 0, 0, 0, 0, GRID_SIZE});
        max_key = _uint256{0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x5D576E73, 0x57A4501D, 0xDFE92F46, 0x681B20A0};
        max_key = cpu_sub_256(max_key, GRID_WORK);
        max_key = cpu_sub_256(max_key, _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK});
        max_key = cpu_add_256(max_key, _uint256{0, 0, 0, 0, 0, 0, 0, 2});
    } else if (mode == 2 || mode == 3) {
        max_key = _uint256{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    }

    _uint256 base_random_key{0, 0, 0, 0, 0, 0, 0, 0};
    _uint256 random_key_increment{0, 0, 0, 0, 0, 0, 0, 0};
    int status;
    if (mode == 0 || mode == 1) {
        status = generate_secure_random_key(base_random_key, max_key, 255);
        random_key_increment = cpu_mul_256_mod_p(cpu_mul_256_mod_p(uint32_to_uint256(BLOCK_SIZE), uint32_to_uint256(GRID_SIZE)), uint32_to_uint256(THREAD_WORK));
    } else if (mode == 2 || mode == 3) {
        status = generate_secure_random_key(base_random_key, max_key, 256);
        random_key_increment = cpu_mul_256_mod_p(cpu_mul_256_mod_p(uint32_to_uint256(BLOCK_SIZE), uint32_to_uint256(GRID_SIZE)), uint32_to_uint256(THREAD_WORK));
        base_random_key.h &= ~(THREAD_WORK - 1);
    }

    if (status) {
        message_queue_mutex.lock();
        message_queue.push(Message{milliseconds(), 10 + status});
        message_queue_mutex.unlock();
        return;
    }
    _uint256 random_key = base_random_key;

    if (mode == 0 || mode == 1) {
        CurvePoint* addends_host = new CurvePoint[THREAD_WORK - 1];
        CurvePoint p = G;
        for (int i = 0; i < THREAD_WORK - 1; i++) {
            addends_host[i] = p;
            p = cpu_point_add(p, G);
        }
        gpu_assert(cudaMemcpyToSymbol(addends, addends_host, (THREAD_WORK - 1) * sizeof(CurvePoint)))
        delete[] addends_host;

        CurvePoint* block_offsets_host = new CurvePoint[GRID_SIZE];
        CurvePoint block_offset = cpu_point_multiply(G, _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK * BLOCK_SIZE});
        p = G;
        for (int i = 0; i < GRID_SIZE; i++) {
            block_offsets_host[i] = p;
            p = cpu_point_add(p, block_offset);
        }
        gpu_assert(cudaMemcpy(block_offsets, block_offsets_host, GRID_SIZE * sizeof(CurvePoint), cudaMemcpyHostToDevice))
        delete[] block_offsets_host;
    }

    if (mode == 0 || mode == 1) {
        cudaStream_t streams[2];
        gpu_assert(cudaStreamCreate(&streams[0]))
        gpu_assert(cudaStreamCreate(&streams[1]))
        
        _uint256 previous_random_key = random_key;
        bool first_iteration = true;
        uint64_t start_time;
        uint64_t end_time;
        double elapsed;

        while (true) {
            if (!first_iteration) {
                if (mode == 0) {
                    gpu_address_work<<<GRID_SIZE, BLOCK_SIZE, 0, streams[0]>>>(score_method, offsets);
                } else {
                    gpu_contract_address_work<<<GRID_SIZE, BLOCK_SIZE, 0, streams[0]>>>(score_method, offsets);
                }
            }

            if (!first_iteration) {
                previous_random_key = random_key;
                random_key = cpu_add_256(random_key, random_key_increment);
                if (gte_256(random_key, max_key)) {
                    random_key = cpu_sub_256(random_key, max_key);
                }
            }
            CurvePoint thread_offset = cpu_point_multiply(G, _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK});
            CurvePoint p = cpu_point_multiply(G, cpu_add_256(_uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK - 1}, random_key));
            for (int i = 0; i < BLOCK_SIZE; i++) {
                thread_offsets_host[i] = p;
                p = cpu_point_add(p, thread_offset);
            }
            gpu_assert(cudaMemcpyToSymbolAsync(thread_offsets, thread_offsets_host, BLOCK_SIZE * sizeof(CurvePoint), 0, cudaMemcpyHostToDevice, streams[1]));
            gpu_assert(cudaStreamSynchronize(streams[1]))
            gpu_assert(cudaStreamSynchronize(streams[0]))

            if (!first_iteration) {
                end_time = milliseconds();
                elapsed = (end_time - start_time) / 1000.0;
            }
            start_time = milliseconds();

            gpu_address_init<<<GRID_SIZE/BLOCK_SIZE, BLOCK_SIZE, 0, streams[0]>>>(block_offsets, offsets);
            if (!first_iteration) {
                gpu_assert(cudaMemcpyFromSymbolAsync(device_memory_host, device_memory, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t), 0, cudaMemcpyDeviceToHost, streams[1]))
                gpu_assert(cudaStreamSynchronize(streams[1]))
            }
            if (!first_iteration) {
                global_max_score_mutex.lock();
                if (output_counter_host[0] != 0) {
                    if (max_score_host[0] > global_max_score) {
                        global_max_score = max_score_host[0];
                    } else {
                        max_score_host[0] = global_max_score;
                    }
                }
                global_max_score_mutex.unlock();

                double speed = GRID_WORK / elapsed / 1000000.0 * 2;
                if (output_counter_host[0] != 0) {
                    int valid_results = 0;

                    for (int i = 0; i < output_counter_host[0]; i++) {
                        if (output_buffer2_host[i] < max_score_host[0]) { continue; }
                        valid_results++;
                    }

                    if (valid_results > 0) {
                        _uint256* results = new _uint256[valid_results];
                        int* scores = new int[valid_results];
                        valid_results = 0;

                        for (int i = 0; i < output_counter_host[0]; i++) {
                            if (output_buffer2_host[i] < max_score_host[0]) { continue; }

                            uint64_t k_offset = output_buffer_host[i];
                            _uint256 k = cpu_add_256(previous_random_key, cpu_add_256(_uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK}, _uint256{0, 0, 0, 0, 0, 0, (uint32_t)(k_offset >> 32), (uint32_t)(k_offset & 0xFFFFFFFF)}));

                            if (output_buffer3_host[i]) {
                                k = cpu_sub_256(N, k);
                            }
                
                            int idx = valid_results++;
                            results[idx] = k;
                            scores[idx] = output_buffer2_host[i];
                        }

                        message_queue_mutex.lock();
                        message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, valid_results, results, scores});
                        message_queue_mutex.unlock();
                    } else {
                        message_queue_mutex.lock();
                        message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                        message_queue_mutex.unlock();
                    }
                } else {
                    message_queue_mutex.lock();
                    message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                    message_queue_mutex.unlock();
                }
            }

            if (!first_iteration) {
                output_counter_host[0] = 0;
                gpu_assert(cudaMemcpyToSymbolAsync(device_memory, device_memory_host, sizeof(uint64_t), 0, cudaMemcpyHostToDevice, streams[1]));
                gpu_assert(cudaStreamSynchronize(streams[1]))
            }
            gpu_assert(cudaStreamSynchronize(streams[0]))
            first_iteration = false;
        }
    }

    if (mode == 2) {
        while (true) {
            uint64_t start_time = milliseconds();
            gpu_contract2_address_work<<<GRID_SIZE, BLOCK_SIZE>>>(score_method, origin_address, random_key, bytecode);

            gpu_assert(cudaDeviceSynchronize())
            gpu_assert(cudaMemcpyFromSymbol(device_memory_host, device_memory, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t)))

            uint64_t end_time = milliseconds();
            double elapsed = (end_time - start_time) / 1000.0;

            global_max_score_mutex.lock();
            if (output_counter_host[0] != 0) {
                if (max_score_host[0] > global_max_score) {
                    global_max_score = max_score_host[0];
                } else {
                    max_score_host[0] = global_max_score;
                }
            }
            global_max_score_mutex.unlock();

            double speed = GRID_WORK / elapsed / 1000000.0;
            if (output_counter_host[0] != 0) {
                int valid_results = 0;

                for (int i = 0; i < output_counter_host[0]; i++) {
                    if (output_buffer2_host[i] < max_score_host[0]) { continue; }
                    valid_results++;
                }

                if (valid_results > 0) {
                    _uint256* results = new _uint256[valid_results];
                    int* scores = new int[valid_results];
                    valid_results = 0;

                    for (int i = 0; i < output_counter_host[0]; i++) {
                        if (output_buffer2_host[i] < max_score_host[0]) { continue; }

                        uint64_t k_offset = output_buffer_host[i];
                        _uint256 k = cpu_add_256(random_key, _uint256{0, 0, 0, 0, 0, 0, (uint32_t)(k_offset >> 32), (uint32_t)(k_offset & 0xFFFFFFFF)});
            
                        int idx = valid_results++;
                        results[idx] = k;
                        scores[idx] = output_buffer2_host[i];
                    }

                    message_queue_mutex.lock();
                    message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, valid_results, results, scores});
                    message_queue_mutex.unlock();
                } else {
                    message_queue_mutex.lock();
                    message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                    message_queue_mutex.unlock();
                }
            } else {
                message_queue_mutex.lock();
                message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                message_queue_mutex.unlock();
            }

            random_key = cpu_add_256(random_key, random_key_increment);

            output_counter_host[0] = 0;
            gpu_assert(cudaMemcpyToSymbol(device_memory, device_memory_host, sizeof(uint64_t)));
        }
    }

    if (mode == 3) {
        while (true) {
            uint64_t start_time = milliseconds();
            gpu_contract3_address_work<<<GRID_SIZE, BLOCK_SIZE>>>(score_method, origin_address, deployer_address, random_key, bytecode);

            gpu_assert(cudaDeviceSynchronize())
            gpu_assert(cudaMemcpyFromSymbol(device_memory_host, device_memory, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t)))

            uint64_t end_time = milliseconds();
            double elapsed = (end_time - start_time) / 1000.0;

            global_max_score_mutex.lock();
            if (output_counter_host[0] != 0) {
                if (max_score_host[0] > global_max_score) {
                    global_max_score = max_score_host[0];
                } else {
                    max_score_host[0] = global_max_score;
                }
            }
            global_max_score_mutex.unlock();

            double speed = GRID_WORK / elapsed / 1000000.0;
            if (output_counter_host[0] != 0) {
                int valid_results = 0;

                for (int i = 0; i < output_counter_host[0]; i++) {
                    if (output_buffer2_host[i] < max_score_host[0]) { continue; }
                    valid_results++;
                }

                if (valid_results > 0) {
                    _uint256* results = new _uint256[valid_results];
                    int* scores = new int[valid_results];
                    valid_results = 0;

                    for (int i = 0; i < output_counter_host[0]; i++) {
                        if (output_buffer2_host[i] < max_score_host[0]) { continue; }

                        uint64_t k_offset = output_buffer_host[i];
                        _uint256 k = cpu_add_256(random_key, _uint256{0, 0, 0, 0, 0, 0, (uint32_t)(k_offset >> 32), (uint32_t)(k_offset & 0xFFFFFFFF)});
            
                        int idx = valid_results++;
                        results[idx] = k;
                        scores[idx] = output_buffer2_host[i];
                    }

                    message_queue_mutex.lock();
                    message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, valid_results, results, scores});
                    message_queue_mutex.unlock();
                } else {
                    message_queue_mutex.lock();
                    message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                    message_queue_mutex.unlock();
                }
            } else {
                message_queue_mutex.lock();
                message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                message_queue_mutex.unlock();
            }

            random_key = cpu_add_256(random_key, random_key_increment);

            output_counter_host[0] = 0;
            gpu_assert(cudaMemcpyToSymbol(device_memory, device_memory_host, sizeof(uint64_t)));
        }
    }
}


void print_speeds(int num_devices, int* device_ids, double* speeds) {
    double total = 0.0;
    for (int i = 0; i < num_devices; i++) {
        total += speeds[i];
    }

    printf("Total: %.2fM/s", total);
    for (int i = 0; i < num_devices; i++) {
        printf("  DEVICE %d: %.2fM/s", device_ids[i], speeds[i]);
    }
}

void print_help() {
    printf("Vanity Eth Address - Generate Ethereum addresses matching specific patterns\n\n");
    printf("Usage: ./vanity [OPTIONS]\n\n");
    printf("Scoring Methods (optional if using --prefix or --suffix):\n");
    printf("  -lz, --leading-zeros          Count leading zero nibbles (scores after prefix if used)\n");
    printf("  -lc, --leading-char <char>    Count leading specific character (scores after prefix if used)\n");
    printf("  -z,  --zeros                  Count zero bytes anywhere in the address\n");
    printf("  -l,  --letters                Count letter characters (a-f) anywhere in the address\n");
    printf("  -n,  --numbers                Count number characters (0-9) anywhere in the address\n\n");
    printf("Modes (optional - default is normal wallet addresses):\n");
    printf("  -c,  --contract               Search for contract addresses (nonce=0)\n");
    printf("  -c2, --contract2              Search for CREATE2 contract addresses\n");
    printf("  -c3, --contract3              Search for CREATE3 proxy contract addresses\n\n");
    printf("Pattern Matching (optional - 3x scoring weight per matching character):\n");
    printf("  -p,  --prefix <pattern>       Match addresses starting with pattern (e.g., 'cafe', '0xdead')\n");
    printf("  -s,  --suffix <pattern>       Match addresses ending with pattern (e.g., 'beef', '1337')\n\n");
    printf("GPU Configuration (required):\n");
    printf("  -d,  --device <number>        Use GPU device <number> (can specify multiple times)\n\n");
    printf("Contract Options (required for --contract2 and --contract3):\n");
    printf("  -b,  --bytecode <file>        Contract bytecode file (hex format)\n");
    printf("  -a,  --address <address>      Origin/sender contract address\n");
    printf("  -da, --deployer-address <addr> Deployer contract address (--contract3 only)\n\n");
    printf("Performance:\n");
    printf("  -w,  --work-scale <num>       Scale work per kernel (default: 15)\n\n");
    printf("Other:\n");
    printf("  -h,  --help                   Show this help message\n\n");
    printf("Examples:\n");
    printf("  ./vanity -lz -d 0                              # Find addresses with leading zeros\n");
    printf("  ./vanity -lc 1 -d 0                            # Find addresses with leading 1s\n");
    printf("  ./vanity -p cafe -d 0                          # Find addresses starting with 'cafe'\n");
    printf("  ./vanity -s beef -d 0                          # Find addresses ending with 'beef'\n");
    printf("  ./vanity -p dead -s beef -d 0                  # Find 0xdead...beef addresses\n");
    printf("  ./vanity -p cafe -lz -d 0                      # Find 0xcafe0000... (zeros after prefix)\n");
    printf("  ./vanity -p dead -lc 1 -d 0                    # Find 0xdead1111... (1s after prefix)\n");
    printf("  ./vanity -lz -s beef -d 0 -d 1                 # Leading zeros + suffix on 2 GPUs\n");
    printf("  ./vanity -z -d 0 -d 1 -d 2 -w 17               # Multi-GPU with custom work scale\n");
    printf("  ./vanity -l -d 0                               # Find addresses with most letters (a-f)\n");
    printf("  ./vanity -n -d 0                               # Find addresses with most numbers (0-9)\n\n");
    printf("Scoring:\n");
    printf("  - Leading zeros: 1 point per hex character (nibble, counted after prefix if used)\n");
    printf("  - Leading char:  1 point per matching character (counted after prefix if used)\n");
    printf("  - Zero bytes:    1 point per zero byte anywhere in address\n");
    printf("  - Letters:       1 point per letter character (a-f) anywhere in address\n");
    printf("  - Numbers:       1 point per number character (0-9) anywhere in address\n");
    printf("  - Prefix match:  3 points per matching character (stops at first mismatch)\n");
    printf("  - Suffix match:  3 points per matching character (stops at first mismatch)\n");
    printf("  - Scores are cumulative: -p cafe -lz scores prefix + zeros after it\n");
    printf("  - Max 10 results printed per score level\n\n");
}

int main(int argc, char *argv[]) {
    // Show help if no arguments provided
    if (argc == 1) {
        print_help();
        return 0;
    }

    int score_method = -1; // 0 = leading zeroes, 1 = zeros, 2 = leading char
    int mode = 0; // 0 = address, 1 = contract, 2 = create2 contract, 3 = create3 proxy contract
    char* input_file = 0;
    char* input_address = 0;
    char* input_deployer_address = 0;
    char* input_prefix = 0;
    char* input_suffix = 0;
    char* input_leading_char = 0;

    uint8_t host_prefix[40];  // prefix nibbles
    int host_prefix_len = 0;
    uint8_t host_suffix[40];  // suffix nibbles, reversed
    int host_suffix_len = 0;
    uint32_t host_leading_char_target = 0;  // target nibble for leading char

    int num_devices = 0;
    int device_ids[32];

    for (int i = 1; i < argc;) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        } else if (strcmp(argv[i], "--device") == 0 || strcmp(argv[i], "-d") == 0) {
            device_ids[num_devices++] = atoi(argv[i + 1]);
            i += 2;
        } else if (strcmp(argv[i], "--leading-zeros") == 0 || strcmp(argv[i], "-lz") == 0) {
            if (score_method != -1) {
                printf("Error: Cannot use multiple scoring methods (-lz, -z, -lc, -l, -n) together\n");
                return 1;
            }
            score_method = 0;
            i++;
        } else if (strcmp(argv[i], "--zeros") == 0 || strcmp(argv[i], "-z") == 0) {
            if (score_method != -1) {
                printf("Error: Cannot use multiple scoring methods (-lz, -z, -lc, -l, -n) together\n");
                return 1;
            }
            score_method = 1;
            i++;
        } else if (strcmp(argv[i], "--leading-char") == 0 || strcmp(argv[i], "-lc") == 0) {
            if (score_method != -1) {
                printf("Error: Cannot use multiple scoring methods (-lz, -z, -lc, -l, -n) together\n");
                return 1;
            }
            score_method = 2;
            input_leading_char = argv[i + 1];
            i += 2;
        } else if (strcmp(argv[i], "--letters") == 0 || strcmp(argv[i], "-l") == 0) {
            if (score_method != -1) {
                printf("Error: Cannot use multiple scoring methods (-lz, -z, -lc, -l, -n) together\n");
                return 1;
            }
            score_method = 3;
            i++;
        } else if (strcmp(argv[i], "--numbers") == 0 || strcmp(argv[i], "-n") == 0) {
            if (score_method != -1) {
                printf("Error: Cannot use multiple scoring methods (-lz, -z, -lc, -l, -n) together\n");
                return 1;
            }
            score_method = 4;
            i++;
        } else if (strcmp(argv[i], "--contract") == 0 || strcmp(argv[i], "-c") == 0) {
            mode = 1;
            i++;
        } else if (strcmp(argv[i], "--contract2") == 0 || strcmp(argv[i], "-c2") == 0) {
            mode = 2;
            i++;
        } else if (strcmp(argv[i], "--contract3") == 0 || strcmp(argv[i], "-c3") == 0) {
            mode = 3;
            i++;
        } else if (strcmp(argv[i], "--bytecode") == 0 || strcmp(argv[i], "-b") == 0) {
            input_file = argv[i + 1];
            i += 2;
        } else if  (strcmp(argv[i], "--address") == 0 || strcmp(argv[i], "-a") == 0) {
            input_address = argv[i + 1];
            i += 2;
        } else if  (strcmp(argv[i], "--deployer-address") == 0 || strcmp(argv[i], "-da") == 0) {
            input_deployer_address = argv[i + 1];
            i += 2;
        } else if  (strcmp(argv[i], "--work-scale") == 0 || strcmp(argv[i], "-w") == 0) {
            GRID_SIZE = 1U << atoi(argv[i + 1]);
            i += 2;
        } else if (strcmp(argv[i], "--prefix") == 0 || strcmp(argv[i], "-p") == 0) {
            input_prefix = argv[i + 1];
            i += 2;
        } else if (strcmp(argv[i], "--suffix") == 0 || strcmp(argv[i], "-s") == 0) {
            input_suffix = argv[i + 1];
            i += 2;
        } else {
            i++;
        }
    }

    if (num_devices == 0) {
        printf("No devices were specified\n");
        return 1;
    }

    // Scoring method is optional if prefix or suffix is provided
    if (score_method == -1 && !input_prefix && !input_suffix) {
        printf("No scoring method or pattern was specified\n");
        printf("You must use one of: --leading-zeros, --leading-char, --zeros, --letters, --numbers, --prefix, or --suffix\n");
        return 1;
    }

    if (mode == 2 && !input_file) {
        printf("You must specify contract bytecode when using --contract2\n");
        return 1;
    }

    if ((mode == 2 || mode == 3) && !input_address) {
        printf("You must specify an origin address when using --contract2\n");
        return 1;
    } else if ((mode == 2 || mode == 3) && strlen(input_address) != 40 && strlen(input_address) != 42) {
        printf("The origin address must be 40 characters long\n");
        return 1;
    }

    if ((mode == 2 || mode == 3) && !input_deployer_address) {
        printf("You must specify a deployer address when using --contract3\n");
        return 1;
    }

    // Parse leading char if provided
    if (score_method == 2) {
        if (!input_leading_char) {
            printf("You must specify a target character when using --leading-char\n");
            return 1;
        }

        // Skip 0x prefix if present
        if (strlen(input_leading_char) >= 2 && input_leading_char[0] == '0' && input_leading_char[1] == 'x') {
            input_leading_char += 2;
        }

        if (strlen(input_leading_char) != 1) {
            printf("Leading char must be exactly one hex character (0-9, a-f)\n");
            return 1;
        }

        char c = input_leading_char[0];
        if (c >= '0' && c <= '9') {
            host_leading_char_target = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            host_leading_char_target = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            host_leading_char_target = c - 'A' + 10;
        } else {
            printf("Invalid hex character '%c' for leading char\n", c);
            return 1;
        }

        // Will be shown in summary below
    }

    // Parse prefix if provided
    if (input_prefix) {
        // Skip 0x prefix if present
        if (strlen(input_prefix) >= 2 && input_prefix[0] == '0' && input_prefix[1] == 'x') {
            input_prefix += 2;
        }
        host_prefix_len = strlen(input_prefix);
        if (host_prefix_len > 40) {
            printf("Prefix cannot be longer than 40 hex characters (20 bytes)\n");
            return 1;
        }
        if (host_prefix_len == 0) {
            printf("Prefix cannot be empty\n");
            return 1;
        }

        // Parse prefix into nibbles (forward order)
        for (int i = 0; i < host_prefix_len; i++) {
            char c = input_prefix[i];
            uint8_t nibble;
            if (c >= '0' && c <= '9') {
                nibble = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                nibble = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                nibble = c - 'A' + 10;
            } else {
                printf("Invalid hex character '%c' in prefix\n", c);
                return 1;
            }
            host_prefix[i] = nibble;
        }
        // Will be shown in summary below
    }

    // Parse suffix if provided
    if (input_suffix) {
        // Skip 0x prefix if present
        if (strlen(input_suffix) >= 2 && input_suffix[0] == '0' && input_suffix[1] == 'x') {
            input_suffix += 2;
        }
        host_suffix_len = strlen(input_suffix);
        if (host_suffix_len > 40) {
            printf("Suffix cannot be longer than 40 hex characters (20 bytes)\n");
            return 1;
        }
        if (host_suffix_len == 0) {
            printf("Suffix cannot be empty\n");
            return 1;
        }

        // Parse suffix into nibbles, reversed (last char of suffix at index 0)
        for (int i = 0; i < host_suffix_len; i++) {
            char c = input_suffix[host_suffix_len - 1 - i];  // reverse order
            uint8_t nibble;
            if (c >= '0' && c <= '9') {
                nibble = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                nibble = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                nibble = c - 'A' + 10;
            } else {
                printf("Invalid hex character '%c' in suffix\n", c);
                return 1;
            }
            host_suffix[i] = nibble;
        }
        // Will be shown in summary below
    }

    // Validate scoring method and prefix/suffix combinations
    if (input_prefix && host_prefix_len > 0) {
        // Check for non-useful combinations: prefix already includes the pattern
        if (score_method == 0) {
            // Check if prefix starts with zeros
            bool all_zeros = true;
            for (int i = 0; i < host_prefix_len; i++) {
                if (host_prefix[i] != 0) {
                    all_zeros = false;
                    break;
                }
            }
            if (all_zeros) {
                printf("Warning: Using --leading-zeros with all-zero prefix '%s' is inefficient\n", input_prefix);
                printf("         The prefix already scores these zeros at 3x weight (%d pts)\n", host_prefix_len * 3);
                printf("         Additional zeros after the prefix score at 1x weight\n");
                printf("         Consider using just --prefix %s if you don't need extra zeros\n", input_prefix);
                printf("\nContinue anyway? (y/n): ");
                char response;
                if (scanf(" %c", &response) != 1 || (response != 'y' && response != 'Y')) {
                    return 1;
                }
            }
        }

        if (score_method == 2) {
            // Check if prefix is all the same character as leading char
            bool all_same = true;
            for (int i = 0; i < host_prefix_len; i++) {
                if (host_prefix[i] != host_leading_char_target) {
                    all_same = false;
                    break;
                }
            }
            if (all_same) {
                char target_char = (host_leading_char_target < 10) ? ('0' + host_leading_char_target) : ('a' + host_leading_char_target - 10);
                printf("Warning: Using --leading-char %c with all-%c prefix '%s' is inefficient\n", target_char, target_char, input_prefix);
                printf("         The prefix already scores these characters at 3x weight (%d pts)\n", host_prefix_len * 3);
                printf("         Additional '%c's after the prefix score at 1x weight\n", target_char);
                printf("         Consider using just --prefix %s if you don't need extra '%c's\n", input_prefix, target_char);
                printf("\nContinue anyway? (y/n): ");
                char response;
                if (scanf(" %c", &response) != 1 || (response != 'y' && response != 'Y')) {
                    return 1;
                }
            }
        }
    }

    for (int i = 0; i < num_devices; i++) {
        cudaError_t e = cudaSetDevice(device_ids[i]);
        if (e != cudaSuccess) {
            printf("Could not detect device %d\n", device_ids[i]);
            return 1;
        }
    }

    #define nothex(n) ((n < 48 || n > 57) && (n < 65 || n > 70) && (n < 97 || n > 102))
    _uint256 bytecode_hash;
    if (mode == 2 || mode == 3) {
        std::ifstream infile(input_file, std::ios::binary);
        if (!infile.is_open()) {
            printf("Failed to open the bytecode file.\n");
            return 1;
        }
        
        int file_size = 0;
        {
            infile.seekg(0, std::ios::end);
            std::streampos file_size_ = infile.tellg();
            infile.seekg(0, std::ios::beg);
            file_size = file_size_ - infile.tellg();
        }

        if (file_size & 1) {
            printf("Invalid bytecode in file.\n");
            return 1;
        }

        uint8_t* bytecode = new uint8_t[24576];
        if (bytecode == 0) {
            printf("Error while allocating memory. Perhaps you are out of memory?");
            return 1;
        }

        char byte[2];
        bool prefix = false;
        for (int i = 0; i < (file_size >> 1); i++) {
            infile.read((char*)&byte, 2);
            if (i == 0) {
                prefix = byte[0] == '0' && byte[1] == 'x';
                if ((file_size >> 1) > (prefix ? 24577 : 24576)) {
                    printf("Invalid bytecode in file.\n");
                    delete[] bytecode;
                    return 1;
                }
                if (prefix) { continue; }
            }

            if (nothex(byte[0]) || nothex(byte[1])) {
                printf("Invalid bytecode in file.\n");
                delete[] bytecode;
                return 1;
            }

            bytecode[i - prefix] = (uint8_t)strtol(byte, 0, 16);
        }    
        bytecode_hash = cpu_full_keccak(bytecode, (file_size >> 1) - prefix);
        delete[] bytecode;
    }

    Address origin_address;
    if (mode == 2 || mode == 3) {
        if (strlen(input_address) == 42) {
            input_address += 2;
        }
        char substr[9];

        #define round(i, offset) \
        strncpy(substr, input_address + offset * 8, 8); \
        if (nothex(substr[0]) || nothex(substr[1]) || nothex(substr[2]) || nothex(substr[3]) || nothex(substr[4]) || nothex(substr[5]) || nothex(substr[6]) || nothex(substr[7])) { \
            printf("Invalid origin address.\n"); \
            return 1; \
        } \
        origin_address.i = strtoull(substr, 0, 16);

        round(a, 0)
        round(b, 1)
        round(c, 2)
        round(d, 3)
        round(e, 4)

        #undef round
    }

    Address deployer_address;
    if (mode == 3) {
        if (strlen(input_deployer_address) == 42) {
            input_deployer_address += 2;
        }
        char substr[9];

        #define round(i, offset) \
        strncpy(substr, input_deployer_address + offset * 8, 8); \
        if (nothex(substr[0]) || nothex(substr[1]) || nothex(substr[2]) || nothex(substr[3]) || nothex(substr[4]) || nothex(substr[5]) || nothex(substr[6]) || nothex(substr[7])) { \
            printf("Invalid deployer address.\n"); \
            return 1; \
        } \
        deployer_address.i = strtoull(substr, 0, 16);

        round(a, 0)
        round(b, 1)
        round(c, 2)
        round(d, 3)
        round(e, 4)

        #undef round
    }
    #undef nothex

    // Copy prefix, suffix, and leading char data to all devices
    for (int i = 0; i < num_devices; i++) {
        cudaSetDevice(device_ids[i]);
        cudaMemcpyToSymbol(device_prefix, host_prefix, sizeof(host_prefix));
        cudaMemcpyToSymbol(device_prefix_len, &host_prefix_len, sizeof(int));
        cudaMemcpyToSymbol(device_suffix, host_suffix, sizeof(host_suffix));
        cudaMemcpyToSymbol(device_suffix_len, &host_suffix_len, sizeof(int));
        cudaMemcpyToSymbol(device_leading_char_target, &host_leading_char_target, sizeof(uint32_t));
    }

    // Print formatted summary
    printf("\n");
    printf("Starting vanity address generation on %d GPU%s\n", num_devices, num_devices == 1 ? "" : "s");

    // Type
    printf("  Type:     ");
    if (mode == 0) printf("Address\n");
    else if (mode == 1) printf("Contract (nonce=0)\n");
    else if (mode == 2) printf("CREATE2\n");
    else if (mode == 3) printf("CREATE3\n");

    // Scoring method
    printf("  Scoring:  ");
    if (score_method == 0) printf("Leading Zeros");
    else if (score_method == 1) printf("Zero Bytes");
    else if (score_method == 2) {
        char c = (host_leading_char_target < 10) ? ('0' + host_leading_char_target) : ('a' + host_leading_char_target - 10);
        printf("Leading Character '%c'", c);
    }
    else if (score_method == 3) printf("Letters (a-f)");
    else if (score_method == 4) printf("Numbers (0-9)");
    else printf("None");

    // Add pattern bonuses
    bool has_pattern = false;
    if (input_prefix && host_prefix_len > 0) {
        if (!has_pattern) printf(" + Patterns");
        has_pattern = true;
    }
    if (input_suffix && host_suffix_len > 0) {
        if (!has_pattern) printf(" + Patterns");
        has_pattern = true;
    }
    printf("\n");

    // Patterns
    if (has_pattern) {
        printf("  Patterns: ");
        if (input_prefix && host_prefix_len > 0) {
            printf("Prefix: 0x%s (bonus: %d)", input_prefix, host_prefix_len * 3);
        }
        if (input_suffix && host_suffix_len > 0) {
            if (input_prefix && host_prefix_len > 0) printf(" & ");
            printf("Suffix: %s (bonus: %d)", input_suffix, host_suffix_len * 3);
        }
        printf("\n");
    }

    printf("\n");

    std::vector<std::thread> threads;
    uint64_t global_start_time = milliseconds();
    for (int i = 0; i < num_devices; i++) {
        std::thread th(host_thread, device_ids[i], i, score_method, mode, origin_address, deployer_address, bytecode_hash);
        threads.push_back(move(th));
    }

    double speeds[100];
    int score_print_count[256] = {0};  // track prints per score (max 10 per score)
    while(true) {
        message_queue_mutex.lock();
        if (message_queue.size() == 0) {
            message_queue_mutex.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        } else {
            while (!message_queue.empty()) {
                Message m = message_queue.front();
                message_queue.pop();

                int device_index = m.device_index;

                if (m.status == 0) {
                    speeds[device_index] = m.speed;

                    printf("\r");
                    if (m.results_count != 0) {
                        Address* addresses = new Address[m.results_count];
                        for (int i = 0; i < m.results_count; i++) {
                            if (mode == 0) {
                                CurvePoint p = cpu_point_multiply(G, m.results[i]);
                                addresses[i] = cpu_calculate_address(p.x, p.y);
                            } else if (mode == 1) {
                                CurvePoint p = cpu_point_multiply(G, m.results[i]);
                                addresses[i] = cpu_calculate_contract_address(cpu_calculate_address(p.x, p.y));
                            } else if (mode == 2) {
                                addresses[i] = cpu_calculate_contract_address2(origin_address, m.results[i], bytecode_hash);
                            } else if (mode == 3) {
                                _uint256 salt = cpu_calculate_create3_salt(origin_address, m.results[i]);
                                Address proxy = cpu_calculate_contract_address2(deployer_address, salt, bytecode_hash);
                                addresses[i] = cpu_calculate_contract_address(proxy, 1);
                            }
                        }

                        for (int i = 0; i < m.results_count; i++) {
                            _uint256 k = m.results[i];
                            int score = m.scores[i];
                            Address a = addresses[i];
                            uint64_t time = (m.time - global_start_time) / 1000;

                            // Limit to 10 prints per score
                            if (score < 256 && score_print_count[score] >= 10) {
                                continue;
                            }
                            score_print_count[score]++;

                            if (mode == 0 || mode == 1) {
                                printf("Elapsed: %06u Score: %02u Private Key: 0x%08x%08x%08x%08x%08x%08x%08x%08x Address: 0x%08x%08x%08x%08x%08x\n", (uint32_t)time, score, k.a, k.b, k.c, k.d, k.e, k.f, k.g, k.h, a.a, a.b, a.c, a.d, a.e);
                            } else if (mode == 2 || mode == 3) {
                                printf("Elapsed: %06u Score: %02u Salt: 0x%08x%08x%08x%08x%08x%08x%08x%08x Address: 0x%08x%08x%08x%08x%08x\n", (uint32_t)time, score, k.a, k.b, k.c, k.d, k.e, k.f, k.g, k.h, a.a, a.b, a.c, a.d, a.e);
                            }
                        }

                        delete[] addresses;
                        delete[] m.results;
                        delete[] m.scores;
                    }
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 1) {
                    printf("\rCuda error %d on device %d. Device will halt work.\n", m.error, device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 11) {
                    printf("\rError from BCryptGenRandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 12) {
                    printf("\rError while reading from /dev/urandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 13) {
                    printf("\rError while opening /dev/urandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 100) {
                    printf("\rError while allocating memory. Perhaps you are out of memory? Device %d will halt work.", device_ids[device_index]);
                }
                // break;
            }
            message_queue_mutex.unlock();
        }
    }
}