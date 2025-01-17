# MOTION-FD: MOTION with Enhanced Support for Function-Dependent Preprocessing

Codebase that was used in our [paper](https://eprint.iacr.org/2023/1744) (IEEE S&P'24).

This is a fork of the MPC framework MOTION ([ePrint](https://ia.cr/2020/1137), [GitHub](https://github.com/encryptogroup/MOTION)) that adds enhanced support for function-dependent preprocessing. More precisely, it supports the following honest majority three-party protocols with function-dependent preprocessing:
* **ASTRA** for the semi-honest security model ([paper](https://eprint.iacr.org/2019/429), CCSW'19)
* **SWIFT** for the malicious security model  ([paper](https://eprint.iacr.org/2020/592), USENIX Security'21) (our code only provides a protocol version without robustness and utilizes triple sacrificing instead of distributed ZK)
* **AUXILIATOR** for a malicious helper ([paper](https://eprint.iacr.org/2023/1744), IEEE S&P'24) (triple sacrifice version)
* **SOCIUM** for a known malicious evaluator ([paper](https://eprint.iacr.org/2023/1744), IEEE S&P'24) (triple sacrifice version)

This code is provided as an experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

## Requirements

* A **Linux distribution** of your choice (MOTION was developed and tested with [Ubuntu](http://www.ubuntu.com/), [Manjaro](https://manjaro.org/) and [Arch Linux](https://www.archlinux.org/), we worked with Manjaro and Arch Linux on x86_64 architecture).
* **Required packages for MOTION:**
  * `g++` (version >=10)
    or another compiler and standard library implementing C++20 including the filesystem library
  * `make`
  * `cmake`
  * [`boost`](https://www.boost.org/) (version >=1.75.0)
  * `OpenMP`
  * [`OpenSSL`](https://www.openssl.org/) (version >=1.1.0)
* This code was tested on:
  * `g++` 13.1.1
  * `make` 4.4.1
  * `cmake` 3.27.0
  * [`boost`](https://www.boost.org/) 1.81.0
  * `OpenMP` 15.0.7
  * [`OpenSSL`](https://www.openssl.org/) 3.1.1

## Building MOTION

For a detailed guide on building and more, we refer to [the MOTION repository](https://github.com/encryptogroup/MOTION)

1. Clone this repository and enter its directory

2. Create and enter the build directory: `mkdir build && cd build`

3. Use CMake configure the build:
    ```
    cmake .. -DMOTION_BUILD_EXE=On -DCMAKE_BUILD_TYPE=Release
    ```
    This also initializes and updates the Git submodules of the dependencies
    located in `extern/`. If one of the dependencies is already installed at a standard location, CMake will try to use the installed version.

4. Call `make` in the build directory.
   Optionally, add `-j $number_of_parallel_jobs` to `make` for faster compilation.
   You can find the build executables and libraries in the directories `bin/`
   and `lib/`, respectively.

## Running the Protocols

Our protocol implementations can be found in `src/motioncore/protocols/`. ASTRA and AUXILIATOR are both bundled in the ASTRA files while SWIFT and SOCIUM are bundled in the SOCIUM files.
Benchmarks for ML inference on the MiniONN architectures for the MNIST and CIFAR-10 datasets can be started as follows (for each party):
```
bin/[PROTOCOL]_benchmark --repetitions=[REPETITIONS] --cnn [CNN] --my-id [ID] --parties 0,[IP0],[PORT0] 1,[IP1],[PORT1] 2,[IP2],[PORT2]
```
with arguments:
* PROTOCOL: `astra`, `auxiliator`, `socium`, or `swift`
* REPETITIONS: Number of repetitions, e.g., `1`
* CNN: `mnist` or `cifar10`
* ID: `0`, `1`, or `2` depending on which party you wish to start
* IP0, IP1, IP2: IPv4 address of the respective party
* PORT0, PORT1, PORT2: Communication port of the respective party

For the CIFAR-10 VGG16 benchmarks, use `-cnn vgg16`.

**Example for running AUXILIATOR on local machine for MNIST:**
```
bin/auxiliator_benchmark --repetitions=1 --cnn mnist --my-id 0 --parties 0,127.0.0.1,23000 1,127.0.0.1,23001 2,127.0.0.1,23002 &
bin/auxiliator_benchmark --repetitions=1 --cnn mnist --my-id 1 --parties 0,127.0.0.1,23000 1,127.0.0.1,23001 2,127.0.0.1,23002 &
bin/auxiliator_benchmark --repetitions=1 --cnn mnist --my-id 2 --parties 0,127.0.0.1,23000 1,127.0.0.1,23001 2,127.0.0.1,23002
```

The benchmarking outputs are written into files `[PROTOCOLNAME]_Benchmark_[CNN]_P[ID].txt` in the `build` directory.
For a simple aggregation of these outputs among all parties, run
```
python3 ../benchmarkparser.py [CNN] [PROTOCOL]
```
from the `build` directory for `CNN` `mnist`, `cifar10` or `vgg16` and protocol `Astra`, `Auxiliator`, `Socium`, or `Swift`.
For the previous example:
```
python3 ../benchmarkparser.py mnist Auxiliator
```
