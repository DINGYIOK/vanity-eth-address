# Vanity Eth Address
Vanity Eth Address is a tool to generate Ethereum addresses that match certain criteria, accelerated with NVIDIA CUDA-enabled GPUs.

## Usage
```
./vanity-eth-addresss [PARAMETERS]
    Scoring methods (optional if using patterns)
      (-lz) --leading-zeros               Count leading zero nibbles (hex chars) in the address
      (-lc) --leading-char <char>         Count leading occurrences of a specific hex character (0-9, a-f)
       (-z) --zeros                       Count zero bytes anywhere in the address
    Modes (normal addresses by default)
       (-c) --contract                    Search for addresses and score the contract address generated using nonce=0
      (-c2) --contract2                   Search for contract addresses using the CREATE2 opcode
      (-c3) --contract3                   Search for contract addresses using a CREATE3 proxy deployer
    Pattern matching (3x scoring weight per matching character):
       (-p) --prefix <pattern>            Match addresses starting with pattern (e.g., "cafe", "0xdead")
       (-s) --suffix <pattern>            Match addresses ending with pattern (e.g., "beef", "1337")
    Other:
       (-d) --device <device_number>      Use device <device_number> (Add one for each device for multi-gpu)
       (-b) --bytecode <filename>         File containing contract bytecode (only needed when using --contract2 or --contract3)
       (-a) --address <address>           Sender contract address (only needed when using --contract2 or --contract3)
      (-ad) --deployer-address <address>  Deployer contract address (only needed when using --contract3)
       (-w) --work-scale <num>            Defaults to 15. Scales the work done in each kernel. If your GPU finishes kernels within a few seconds, you may benefit from increasing this number.

Examples:
    ./vanity-eth-address --zeros --device 0 --device 2 --work-scale 17
    ./vanity-eth-address --leading-zeros --contract2 --bytecode bytecode.txt --address 0x0000000000000000000000000000000000000000 --device 0
    ./vanity-eth-address --prefix cafe --device 0
    ./vanity-eth-address --suffix beef --device 0
    ./vanity-eth-address --prefix dead --suffix beef --device 0
    ./vanity-eth-address --prefix cafe --leading-zeros --device 0       # Find 0xcafe0000... (zeros after prefix)
    ./vanity-eth-address --prefix dead --leading-char 1 --device 0      # Find 0xdead1111... (1s after prefix)
    ./vanity-eth-address --leading-char 1 --device 0
    ./vanity-eth-address --leading-zeros --suffix beef --device 0 --device 1
    ./vanity-eth-address --leading-zeros --prefix dead --suffix 1337 --contract --device 0
```

## Benchmarks
| GPU  | Normal addresses | Contract addresses | CREATE2 addresses |
| ---- | ---------------- | ------------------ | ----------------- |
| 4090 | 3800M/s          | 2050M/s            | 4800M/s           |
| 3090 | 1600M/s          | 850M/s             | 2300M/s           |
| 3070 | 1000M/s          | 550M/s             | 1300M/s           |

Note that configuration and environment can affect performance.

## Requirements
* A NVIDIA CUDA-enabled GPU with a compute capability of at least 5.2 (Roughly anything above a GeForce GTX 950. For a full list [see here](https://developer.nvidia.com/cuda-gpus)).