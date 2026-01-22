/*
    简化的以太坊地址生成器
    从 pipei.txt 读取前缀*后缀模式
    生成匹配的地址和私钥到 dizhi.txt
*/

#if defined(_WIN64)
    #define WIN32_NO_STATUS
    #include <windows.h>
    #undef WIN32_NO_STATUS
#endif

#include <thread>
#include <cinttypes>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <mutex>
#include <queue>
#include <chrono>
#include <sstream>
#include <atomic>

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

// 使用动态分配的全局内存结构体
struct DevicePatternData {
    uint8_t prefix[40];
    int prefix_len;
    uint8_t suffix[40];
    int suffix_len;
    uint64_t memory[2 + OUTPUT_BUFFER_SIZE * 3];
};

// 声明全局设备指针，在 kernel 中使用
__device__ DevicePatternData* g_device_pattern = nullptr;

// 前缀匹配函数
__device__ bool match_prefix(Address a, const DevicePatternData* pattern) {
    if (pattern->prefix_len == 0) return true;
    
    uint32_t parts[5] = {a.a, a.b, a.c, a.d, a.e};
    
    for (int i = 0; i < pattern->prefix_len; i++) {
        int part_idx = i / 8;
        int nibble_idx = 7 - (i % 8);
        
        uint8_t addr_nibble = (parts[part_idx] >> (nibble_idx * 4)) & 0xF;
        if (addr_nibble != pattern->prefix[i]) {
            return false;
        }
    }
    return true;
}

// 后缀匹配函数
__device__ bool match_suffix(Address a, const DevicePatternData* pattern) {
    if (pattern->suffix_len == 0) return true;
    
    uint32_t parts[5] = {a.e, a.d, a.c, a.b, a.a};
    
    for (int i = 0; i < pattern->suffix_len; i++) {
        int part_idx = i / 8;
        int nibble_idx = i % 8;
        
        uint8_t addr_nibble = (parts[part_idx] >> (nibble_idx * 4)) & 0xF;
        if (addr_nibble != pattern->suffix[i]) {
            return false;
        }
    }
    return true;
}

#ifdef __linux__
    #define atomicAdd_ul(a, b) atomicAdd((unsigned long long*)(a), (unsigned long long)(b))
#else
    #define atomicAdd_ul(a, b) atomicAdd(a, b)
#endif

// handle_output 函数 - 使用全局设备指针
__device__ void handle_output(int score_method, Address a, uint64_t key, bool inv) {
    DevicePatternData* pattern = g_device_pattern;
    if (pattern && match_prefix(a, pattern) && match_suffix(a, pattern)) {
        uint32_t idx = atomicAdd_ul(&pattern->memory[0], 1);
        if (idx < OUTPUT_BUFFER_SIZE) {
            pattern->memory[2 + idx] = key;
            pattern->memory[OUTPUT_BUFFER_SIZE * 2 + 2 + idx] = inv;
        }
    }
}

// 包含原有的 address.h，它会使用上面定义的 handle_output
#include "address.h"

uint64_t milliseconds() {
    return (std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch())).count();
}

struct PatternMatch {
    _uint256 private_key;
    Address address;
};

struct Message {
    int status;  // 0=success, 1=error, 2=stop_requested
    int device_index;
    cudaError_t error;
    std::string error_msg;
    std::vector<PatternMatch> matches;
};

std::queue<Message> message_queue;
std::mutex message_queue_mutex;
std::mutex output_mutex;
std::ofstream output_file;

uint32_t GRID_SIZE = 1U << 15;

// 全局停止标志
std::atomic<bool> stop_all_threads(false);
std::atomic<bool> pattern_found(false);

struct Pattern {
    std::string prefix;
    std::string suffix;
    uint8_t prefix_nibbles[40];
    int prefix_len;
    uint8_t suffix_nibbles[40];
    int suffix_len;
};

void host_thread(int device, int device_index, const Pattern& pattern) {
    CurvePoint* block_offsets = 0;
    CurvePoint* offsets = 0;
    CurvePoint* thread_offsets_host = 0;
    DevicePatternData* device_pattern = 0;
    DevicePatternData* host_pattern = 0;
    DevicePatternData** d_pattern_ptr = 0;
    
    cudaError_t e;
    
    std::cout << "[GPU " << device_index << "] 开始初始化..." << std::endl;
    
    e = cudaSetDevice(device);
    if (e != cudaSuccess) {
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaSetDevice 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] cudaSetDevice 成功" << std::endl;
    
    // 分配 host 端模式数据
    e = cudaHostAlloc(&host_pattern, sizeof(DevicePatternData), cudaHostAllocDefault);
    if (e != cudaSuccess) {
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaHostAlloc host_pattern 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] cudaHostAlloc host_pattern 成功" << std::endl;
    
    // 初始化模式数据
    memcpy(host_pattern->prefix, pattern.prefix_nibbles, 40);
    host_pattern->prefix_len = pattern.prefix_len;
    memcpy(host_pattern->suffix, pattern.suffix_nibbles, 40);
    host_pattern->suffix_len = pattern.suffix_len;
    host_pattern->memory[0] = 0;
    host_pattern->memory[1] = 0;
    
    std::cout << "[GPU " << device_index << "] 模式数据: prefix_len=" << host_pattern->prefix_len 
              << ", suffix_len=" << host_pattern->suffix_len << std::endl;
    
    // 分配 device 端模式数据
    e = cudaMalloc(&device_pattern, sizeof(DevicePatternData));
    if (e != cudaSuccess) {
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaMalloc device_pattern 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] cudaMalloc device_pattern 成功 (地址: " << device_pattern << ")" << std::endl;
    
    // 复制模式数据到设备
    e = cudaMemcpy(device_pattern, host_pattern, sizeof(DevicePatternData), cudaMemcpyHostToDevice);
    if (e != cudaSuccess) {
        cudaFree(device_pattern);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaMemcpy device_pattern 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] cudaMemcpy device_pattern 成功" << std::endl;
    
    // 设置全局设备指针
    e = cudaMemcpyToSymbol(&g_device_pattern, &device_pattern, sizeof(DevicePatternData*), 0, cudaMemcpyHostToDevice);
    if (e != cudaSuccess) {
        cudaFree(device_pattern);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaMemcpyToSymbol g_device_pattern 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] cudaMemcpyToSymbol g_device_pattern 成功" << std::endl;
    
    // 同步确保复制完成
    e = cudaDeviceSynchronize();
    if (e != cudaSuccess) {
        cudaFree(device_pattern);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "模式数据同步失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] 模式数据同步成功" << std::endl;
    
    // 分配其他内存
    e = cudaMalloc(&block_offsets, GRID_SIZE * sizeof(CurvePoint));
    if (e != cudaSuccess) {
        cudaFree(device_pattern);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaMalloc block_offsets 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] cudaMalloc block_offsets 成功" << std::endl;
    
    e = cudaMalloc(&offsets, (uint64_t)GRID_SIZE * BLOCK_SIZE * sizeof(CurvePoint));
    if (e != cudaSuccess) {
        cudaFree(block_offsets);
        cudaFree(device_pattern);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaMalloc offsets 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] cudaMalloc offsets 成功" << std::endl;
    
    e = cudaHostAlloc(&thread_offsets_host, BLOCK_SIZE * sizeof(CurvePoint), 
        cudaHostAllocWriteCombined);
    if (e != cudaSuccess) {
        cudaFree(offsets);
        cudaFree(block_offsets);
        cudaFree(device_pattern);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaHostAlloc thread_offsets_host 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] cudaHostAlloc thread_offsets_host 成功" << std::endl;
    
    // 初始化常量
    CurvePoint* addends_host = new CurvePoint[THREAD_WORK - 1];
    CurvePoint p = G;
    for (int i = 0; i < THREAD_WORK - 1; i++) {
        addends_host[i] = p;
        p = cpu_point_add(p, G);
    }
    e = cudaMemcpyToSymbol(&addends, addends_host, (THREAD_WORK - 1) * sizeof(CurvePoint), 0, cudaMemcpyHostToDevice);
    delete[] addends_host;
    if (e != cudaSuccess) {
        cudaFree(offsets);
        cudaFree(block_offsets);
        cudaFree(device_pattern);
        cudaFreeHost(thread_offsets_host);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "复制 addends 常量失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] 复制 addends 常量成功" << std::endl;
    
    CurvePoint* block_offsets_host = new CurvePoint[GRID_SIZE];
    CurvePoint block_offset = cpu_point_multiply(G, 
        _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK * BLOCK_SIZE});
    p = G;
    for (int i = 0; i < GRID_SIZE; i++) {
        block_offsets_host[i] = p;
        p = cpu_point_add(p, block_offset);
    }
    e = cudaMemcpy(block_offsets, block_offsets_host, 
        GRID_SIZE * sizeof(CurvePoint), cudaMemcpyHostToDevice);
    delete[] block_offsets_host;
    if (e != cudaSuccess) {
        cudaFree(offsets);
        cudaFree(block_offsets);
        cudaFree(device_pattern);
        cudaFreeHost(thread_offsets_host);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "复制 block_offsets 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] 复制 block_offsets 成功" << std::endl;
    
    // 生成随机起始密钥
    _uint256 max_key = _uint256{0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 
        0x5D576E73, 0x57A4501D, 0xDFE92F46, 0x681B20A0};
    _uint256 GRID_WORK_256 = cpu_mul_256_mod_p(
        cpu_mul_256_mod_p(_uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK}, 
            _uint256{0, 0, 0, 0, 0, 0, 0, BLOCK_SIZE}), 
        _uint256{0, 0, 0, 0, 0, 0, 0, GRID_SIZE});
    max_key = cpu_sub_256(max_key, GRID_WORK_256);
    max_key = cpu_sub_256(max_key, _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK});
    max_key = cpu_add_256(max_key, _uint256{0, 0, 0, 0, 0, 0, 0, 2});
    
    _uint256 random_key;
    int status = generate_secure_random_key(random_key, max_key, 255);
    if (status) {
        cudaFree(offsets);
        cudaFree(block_offsets);
        cudaFree(device_pattern);
        cudaFreeHost(thread_offsets_host);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = cudaSuccess;
        msg.error_msg = "生成随机密钥失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] 生成随机密钥成功" << std::endl;
    
    _uint256 random_key_increment = cpu_mul_256_mod_p(
        cpu_mul_256_mod_p(uint32_to_uint256(BLOCK_SIZE), uint32_to_uint256(GRID_SIZE)), 
        uint32_to_uint256(THREAD_WORK));
    
    cudaStream_t streams[2];
    e = cudaStreamCreate(&streams[0]);
    if (e != cudaSuccess) {
        cudaFree(offsets);
        cudaFree(block_offsets);
        cudaFree(device_pattern);
        cudaFreeHost(thread_offsets_host);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaStreamCreate streams[0] 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    
    e = cudaStreamCreate(&streams[1]);
    if (e != cudaSuccess) {
        cudaStreamDestroy(streams[0]);
        cudaFree(offsets);
        cudaFree(block_offsets);
        cudaFree(device_pattern);
        cudaFreeHost(thread_offsets_host);
        cudaFreeHost(host_pattern);
        message_queue_mutex.lock();
        Message msg;
        msg.status = 1;
        msg.device_index = device_index;
        msg.error = e;
        msg.error_msg = "cudaStreamCreate streams[1] 失败";
        message_queue.push(msg);
        message_queue_mutex.unlock();
        return;
    }
    std::cout << "[GPU " << device_index << "] 创建 CUDA streams 成功" << std::endl;
    std::cout << "[GPU " << device_index << "] 初始化完成，开始搜索..." << std::endl;
    
    _uint256 previous_random_key = random_key;
    bool first_iteration = true;
    
    while (!stop_all_threads.load() && !pattern_found.load()) {
        if (!first_iteration) {
            gpu_address_work<<<GRID_SIZE, BLOCK_SIZE, 0, streams[0]>>>(0, offsets);
            e = cudaGetLastError();
            if (e != cudaSuccess) {
                cudaStreamDestroy(streams[0]);
                cudaStreamDestroy(streams[1]);
                cudaFree(offsets);
                cudaFree(block_offsets);
                cudaFree(device_pattern);
                cudaFreeHost(thread_offsets_host);
                cudaFreeHost(host_pattern);
                message_queue_mutex.lock();
                Message msg;
                msg.status = 1;
                msg.device_index = device_index;
                msg.error = e;
                msg.error_msg = "gpu_address_work kernel 启动失败";
                message_queue.push(msg);
                message_queue_mutex.unlock();
                return;
            }
        }
        
        if (!first_iteration) {
            previous_random_key = random_key;
            random_key = cpu_add_256(random_key, random_key_increment);
            if (gte_256(random_key, max_key)) {
                random_key = cpu_sub_256(random_key, max_key);
            }
        }
        
        CurvePoint thread_offset = cpu_point_multiply(G, 
            _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK});
        p = cpu_point_multiply(G, cpu_add_256(
            _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK - 1}, random_key));
        for (int i = 0; i < BLOCK_SIZE; i++) {
            thread_offsets_host[i] = p;
            p = cpu_point_add(p, thread_offset);
        }
        
        e = cudaMemcpyToSymbolAsync(&thread_offsets, thread_offsets_host, 
            BLOCK_SIZE * sizeof(CurvePoint), 0, cudaMemcpyHostToDevice, streams[1]);
        if (e != cudaSuccess) {
            cudaStreamDestroy(streams[0]);
            cudaStreamDestroy(streams[1]);
            cudaFree(offsets);
            cudaFree(block_offsets);
            cudaFree(device_pattern);
            cudaFreeHost(thread_offsets_host);
            cudaFreeHost(host_pattern);
            message_queue_mutex.lock();
            Message msg;
            msg.status = 1;
            msg.device_index = device_index;
            msg.error = e;
            msg.error_msg = "复制 thread_offsets 失败";
            message_queue.push(msg);
            message_queue_mutex.unlock();
            return;
        }
        
        cudaStreamSynchronize(streams[1]);
        cudaStreamSynchronize(streams[0]);
        
        gpu_address_init<<<GRID_SIZE/BLOCK_SIZE, BLOCK_SIZE, 0, streams[0]>>>(
            block_offsets, offsets);
        e = cudaGetLastError();
        if (e != cudaSuccess) {
            cudaStreamDestroy(streams[0]);
            cudaStreamDestroy(streams[1]);
            cudaFree(offsets);
            cudaFree(block_offsets);
            cudaFree(device_pattern);
            cudaFreeHost(thread_offsets_host);
            cudaFreeHost(host_pattern);
            message_queue_mutex.lock();
            Message msg;
            msg.status = 1;
            msg.device_index = device_index;
            msg.error = e;
            msg.error_msg = "gpu_address_init kernel 启动失败";
            message_queue.push(msg);
            message_queue_mutex.unlock();
            return;
        }
        
        if (!first_iteration) {
            e = cudaMemcpyAsync(host_pattern, device_pattern, sizeof(DevicePatternData),
                cudaMemcpyDeviceToHost, streams[1]);
            if (e != cudaSuccess) {
                cudaStreamDestroy(streams[0]);
                cudaStreamDestroy(streams[1]);
                cudaFree(offsets);
                cudaFree(block_offsets);
                cudaFree(device_pattern);
                cudaFreeHost(thread_offsets_host);
                cudaFreeHost(host_pattern);
                message_queue_mutex.lock();
                Message msg;
                msg.status = 1;
                msg.device_index = device_index;
                msg.error = e;
                msg.error_msg = "从 device_pattern 复制结果失败";
                message_queue.push(msg);
                message_queue_mutex.unlock();
                return;
            }
            cudaStreamSynchronize(streams[1]);
            
            if (host_pattern->memory[0] > 0) {
                std::vector<PatternMatch> matches;
                
                for (uint64_t i = 0; i < host_pattern->memory[0] && i < OUTPUT_BUFFER_SIZE; i++) {
                    uint64_t k_offset = host_pattern->memory[2 + i];
                    _uint256 k = cpu_add_256(previous_random_key, cpu_add_256(
                        _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK}, 
                        _uint256{0, 0, 0, 0, 0, 0, (uint32_t)(k_offset >> 32), 
                            (uint32_t)(k_offset & 0xFFFFFFFF)}));
                    
                    if (host_pattern->memory[OUTPUT_BUFFER_SIZE * 2 + 2 + i]) {
                        k = cpu_sub_256(N, k);
                    }
                    
                    CurvePoint point = cpu_point_multiply(G, k);
                    Address addr = cpu_calculate_address(point.x, point.y);
                    
                    matches.push_back({k, addr});
                }
                
                if (!matches.empty()) {
                    message_queue_mutex.lock();
                    Message msg;
                    msg.status = 0;
                    msg.device_index = device_index;
                    msg.error = cudaSuccess;
                    msg.matches = matches;
                    message_queue.push(msg);
                    message_queue_mutex.unlock();
                    
                    // 找到匹配，设置标志
                    pattern_found.store(true);
                }
            }
            
            // 重置计数器
            host_pattern->memory[0] = 0;
            e = cudaMemcpyAsync(device_pattern, host_pattern, sizeof(uint64_t),
                cudaMemcpyHostToDevice, streams[1]);
            if (e != cudaSuccess) {
                cudaStreamDestroy(streams[0]);
                cudaStreamDestroy(streams[1]);
                cudaFree(offsets);
                cudaFree(block_offsets);
                cudaFree(device_pattern);
                cudaFreeHost(thread_offsets_host);
                cudaFreeHost(host_pattern);
                message_queue_mutex.lock();
                Message msg;
                msg.status = 1;
                msg.device_index = device_index;
                msg.error = e;
                msg.error_msg = "重置 device_pattern 计数器失败";
                message_queue.push(msg);
                message_queue_mutex.unlock();
                return;
            }
            cudaStreamSynchronize(streams[1]);
        }
        
        cudaStreamSynchronize(streams[0]);
        first_iteration = false;
    }
    
    std::cout << "[GPU " << device_index << "] 搜索结束，清理资源..." << std::endl;
    
    // 清理资源
    cudaStreamDestroy(streams[0]);
    cudaStreamDestroy(streams[1]);
    cudaFree(offsets);
    cudaFree(block_offsets);
    cudaFree(device_pattern);
    cudaFreeHost(thread_offsets_host);
    cudaFreeHost(host_pattern);
    
    std::cout << "[GPU " << device_index << "] 资源清理完成" << std::endl;
}

bool parse_hex_char(char c, uint8_t& nibble) {
    if (c >= '0' && c <= '9') {
        nibble = c - '0';
        return true;
    } else if (c >= 'a' && c <= 'f') {
        nibble = c - 'a' + 10;
        return true;
    } else if (c >= 'A' && c <= 'F') {
        nibble = c - 'A' + 10;
        return true;
    }
    return false;
}

bool parse_pattern(const std::string& line, Pattern& pattern) {
    size_t star_pos = line.find('*');
    if (star_pos == std::string::npos) {
        return false;
    }
    
    std::string prefix_str = line.substr(0, star_pos);
    std::string suffix_str = line.substr(star_pos + 1);
    
    // 移除 0x 前缀
    if (prefix_str.length() >= 2 && prefix_str[0] == '0' && prefix_str[1] == 'x') {
        prefix_str = prefix_str.substr(2);
    }
    if (suffix_str.length() >= 2 && suffix_str[0] == '0' && suffix_str[1] == 'x') {
        suffix_str = suffix_str.substr(2);
    }
    
    pattern.prefix = prefix_str;
    pattern.suffix = suffix_str;
    pattern.prefix_len = prefix_str.length();
    pattern.suffix_len = suffix_str.length();
    
    if (pattern.prefix_len > 40 || pattern.suffix_len > 40) {
        return false;
    }
    
    // 解析前缀
    for (int i = 0; i < pattern.prefix_len; i++) {
        if (!parse_hex_char(prefix_str[i], pattern.prefix_nibbles[i])) {
            return false;
        }
    }
    
    // 解析后缀（反向存储）
    for (int i = 0; i < pattern.suffix_len; i++) {
        if (!parse_hex_char(suffix_str[pattern.suffix_len - 1 - i], 
            pattern.suffix_nibbles[i])) {
            return false;
        }
    }
    
    return true;
}

std::string address_to_string(const Address& addr) {
    char buf[43];
    snprintf(buf, sizeof(buf), "0x%08x%08x%08x%08x%08x", 
        addr.a, addr.b, addr.c, addr.d, addr.e);
    return std::string(buf);
}

std::string key_to_string(const _uint256& key) {
    char buf[67];
    snprintf(buf, sizeof(buf), "0x%08x%08x%08x%08x%08x%08x%08x%08x",
        key.a, key.b, key.c, key.d, key.e, key.f, key.g, key.h);
    return std::string(buf);
}

int main() {
    std::cout << "=== 以太坊地址生成器启动 ===" << std::endl;
    
    // 读取模式文件
    std::ifstream pattern_file("pipei.txt");
    if (!pattern_file.is_open()) {
        std::cerr << "错误: 无法打开 pipei.txt 文件" << std::endl;
        return 1;
    }
    
    std::vector<Pattern> patterns;
    std::string line;
    int line_num = 0;
    
    while (std::getline(pattern_file, line)) {
        line_num++;
        if (line.empty()) continue;
        
        Pattern pattern;
        if (!parse_pattern(line, pattern)) {
            std::cerr << "警告: 第 " << line_num << " 行格式错误: " << line << std::endl;
            continue;
        }
        patterns.push_back(pattern);
    }
    pattern_file.close();
    
    if (patterns.empty()) {
        std::cerr << "错误: 没有找到有效的模式" << std::endl;
        return 1;
    }
    
    std::cout << "成功加载 " << patterns.size() << " 个匹配模式" << std::endl;
    
    // 检测可用的 GPU
    int num_devices;
    cudaError_t e = cudaGetDeviceCount(&num_devices);
    if (e != cudaSuccess) {
        std::cerr << "错误: cudaGetDeviceCount 失败: " << cudaGetErrorString(e) << std::endl;
        return 1;
    }
    
    if (num_devices == 0) {
        std::cerr << "错误: 未检测到可用的 GPU" << std::endl;
        return 1;
    }
    
    std::cout << "检测到 " << num_devices << " 个 GPU" << std::endl;
    
    // 验证所有GPU都可用
    for (int i = 0; i < num_devices; i++) {
        e = cudaSetDevice(i);
        if (e != cudaSuccess) {
            std::cerr << "错误: 无法访问 GPU " << i << ": " << cudaGetErrorString(e) << std::endl;
            return 1;
        }
        
        cudaDeviceProp prop;
        e = cudaGetDeviceProperties(&prop, i);
        if (e != cudaSuccess) {
            std::cerr << "警告: 无法获取 GPU " << i << " 属性: " << cudaGetErrorString(e) << std::endl;
        } else {
            std::cout << "  GPU " << i << ": " << prop.name << std::endl;
        }
    }
    
    // 打开输出文件
    output_file.open("dizhi.txt", std::ios::app);
    if (!output_file.is_open()) {
        std::cerr << "错误: 无法打开 dizhi.txt 文件" << std::endl;
        return 1;
    }
    
    std::cout << "\n=== 开始处理模式 ===" << std::endl;
    
    // 处理每个模式
    for (size_t pattern_idx = 0; pattern_idx < patterns.size(); pattern_idx++) {
        const Pattern& pattern = patterns[pattern_idx];
        
        std::cout << "\n[" << (pattern_idx + 1) << "/" << patterns.size() 
                  << "] 正在搜索: 0x" << pattern.prefix << "..." << pattern.suffix << std::endl;
        
        // 重置标志
        stop_all_threads.store(false);
        pattern_found.store(false);
        
        // 启动工作线程
        std::vector<std::thread> threads;
        for (int i = 0; i < num_devices; i++) {
            threads.push_back(std::thread(host_thread, i, i, std::ref(pattern)));
        }
        
        // 等待找到第一个匹配
        bool found = false;
        uint64_t start_time = milliseconds();
        
        while (!found) {
            message_queue_mutex.lock();
            while (!message_queue.empty()) {
                Message m = message_queue.front();
                message_queue.pop();
                
                if (m.status == 1) {
                    // 错误发生
                    std::cerr << "GPU " << m.device_index << " 发生错误: ";
                    if (!m.error_msg.empty()) {
                        std::cerr << m.error_msg << " - ";
                    }
                    std::cerr << cudaGetErrorString(m.error) << std::endl;
                } else if (m.status == 0 && !m.matches.empty()) {
                    // 找到匹配，写入文件
                    output_mutex.lock();
                    for (const auto& match : m.matches) {
                        std::string addr_str = address_to_string(match.address);
                        std::string key_str = key_to_string(match.private_key);
                        output_file << addr_str << "---" << key_str << std::endl;
                        output_file.flush();
                        
                        uint64_t elapsed = (milliseconds() - start_time) / 1000;
                        std::cout << "✓ 找到匹配 (用时 " << elapsed << "s): " << addr_str << std::endl;
                        found = true;
                        break;
                    }
                    output_mutex.unlock();
                }
            }
            message_queue_mutex.unlock();
            
            if (!found) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        
        // 设置停止标志，等待所有线程退出
        stop_all_threads.store(true);
        pattern_found.store(true);
        
        std::cout << "等待所有 GPU 线程退出..." << std::endl;
        for (auto& th : threads) {
            if (th.joinable()) {
                th.join();
            }
        }
        std::cout << "所有 GPU 线程已退出" << std::endl;
        
        // 清空消息队列
        message_queue_mutex.lock();
        while (!message_queue.empty()) {
            message_queue.pop();
        }
        message_queue_mutex.unlock();
        
        // 短暂延迟确保资源完全释放
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    output_file.close();
    std::cout << "\n✓ 所有模式处理完成！结果已保存到 dizhi.txt" << std::endl;
    
    return 0;
}

/**
nvcc -O3 -rdc=true -gencode=arch=compute_89,code=sm_89 -I ../src -o main.exe main.cu

*/