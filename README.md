# anonymous-submission
Lazy-Batched Key-Switching Framework for Accelerating Homomorphic Evaluation

## Requirements
- C++ compiler (g++ ≥ 9.4.0)
- CMake (≥ 3.5)
- Git

## Repository Layout
    .
    ├── app/
    │   └── mat-mult/          # Application-level evaluation (matrix multiplication)
    ├── benchmark/             # Microbenchmarks for the proposed framework
    │   ├── build/
    │   ├── CMakeLists.txt
    │   └── measure-batched-ks.cpp
    ├── LICENSE
    ├── openfhe-development/   # Vendored copy of OpenFHE with our extensions (not a submodule)
    └── README.md

### Notes on OpenFHE
- `openfhe-development/` is a **vendored snapshot** (file copy) that includes our lazy-batched key-switching code.
- It is **not** a git submodule or live fork.
- The original OpenFHE LICENSE is retained under `openfhe-development/`.

## Build the Vendored OpenFHE (inside this repo)
    cd openfhe-development
    mkdir build && cd build
    cmake ..
    make -j
    sudo make install      # or set a local prefix via: cmake .. -DCMAKE_INSTALL_PREFIX=$PWD/local && make -j && make install

## Run Microbenchmarks
    cd benchmark
    mkdir build && cd build
    cmake ..
    make -j
    ./measure-batched-ks
- Prints results to console and writes CSV files in the current build directory.

## Run Application-Level Evaluations (matrix multiplication)
    cd app/mat-mult
    mkdir build && cd build
    cmake ..
    make -j
    ./ar24-test
    ./jkls18-test
- Each executable prints results to console and writes CSV files in the current build directory.

## References
- **JKLS18**  
  Xiaoqian Jiang, Miran Kim, Kristin E. Lauter, and Yongsoo Song.  
  *Secure Outsourced Matrix Computation and Application to Neural Networks.*  
  Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security (CCS 2018), pp. 1209–1222, 2018.  
  <https://eprint.iacr.org/2018/1041.pdf>

- **AR24**  
  Aikata Aikata and Sujoy Sinha Roy.  
  *Secure and Efficient Outsourced Matrix Multiplication with Homomorphic Encryption.*  
  Progress in Cryptology – INDOCRYPT 2024, 25th International Conference, Part I.  
  <https://eprint.iacr.org/2024/1730.pdf>


## License
- This repository: MIT (see `LICENSE`).
- `openfhe-development/`: original OpenFHE license retained.
