# 🔒 ZK-Auth: High-Performance Zero-Knowledge Authentication

A highly optimized zero-knowledge proof-based authentication system built in Rust with Actix-Web. This system enables users to prove their identity without revealing sensitive personal information, using Groth16 zk-SNARKs and optimized Poseidon hash functions.

## ⚡ Performance Highlights

- **Optimized Poseidon Hashing**: Pre-cached hashers eliminate initialization overhead
- **Pre-computed Verification Keys**: Faster proof verification using prepared keys  
- **Concurrent Proof Generation**: Semaphore-controlled parallel processing
- **Efficient Serialization**: Minimized memory allocations and field conversions
- **Fast Random Number Generation**: Optimized RNG for cryptographic operations

## 🌟 Features

- **Zero-Knowledge Authentication**: Prove identity without revealing personal data
- **High Performance**: Rust + Actix-Web with extensive optimizations
- **Groth16 Proofs**: Industry-standard zk-SNARK implementation
- **Cached Cryptography**: Pre-initialized Poseidon hashers and verification keys
- **Resource Management**: Smart concurrency control for optimal throughput
- **Comprehensive Benchmarking**: Built-in performance testing tools

## 🏗️ Architecture

### Core Components

1. **Registration Service** (`/register`): Generates commitments from user data
2. **Proof Generation** (`/generate-proof`): Creates zero-knowledge proofs of identity  
3. **Verification Service** (`/verify-proof`): Validates proofs without revealing secrets
4. **ZK Circuit**: Circom-based circuit for proving knowledge of secrets

### System Flow

```
User Data → Hash → Secret → Commitment → ZK Proof → Verification
```

1. User provides personal information (email, name, age, country, DOB)
2. System hashes this data using Keccak256 and optimized Poseidon
3. A secret is derived and a commitment is generated
4. User can later generate ZK proofs to authenticate without revealing the original data
5. Verifiers can validate these proofs using only the commitment

## 📋 Prerequisites

### System Requirements

- **Rust**: 1.70+ with Cargo
- **Node.js**: 16+ with npm/pnpm (for benchmarking)
- **RAM**: 8GB+ (proof generation is memory-intensive)
- **CPU**: Multi-core recommended for concurrent proof generation

## 🚀 Installation

### 1. Clone Repository

```bash
git clone https://github.com/FocusBT/zk-auth-rust.git
cd zk-auth-rust
```

### 2. Install Rust Dependencies

```bash
# Debug build
cargo build

# Optimized release build (recommended)
cargo build --release
```

### 3. Install Node.js Dependencies (for benchmarking)

```bash
# Using pnpm (recommended)
pnpm install

# Or using npm
npm install
```

## 🔧 Usage

### Starting the Server

```bash
# Development mode
cargo run

# Production mode (optimized)
./target/release/zk-auth-api
```

The server will start on `http://localhost:8080`

### API Endpoints

#### 1. Register User

**POST** `/register`

Generates a commitment for user authentication.

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "name": "Alice Doe",
    "age": 30,
    "country": "US",
    "dob": "1994-01-15"
  }'
```

**Response:**
```json
{
  "secret": "0x1234...",
  "nonce": "0x5678...",
  "commitment": "123456789..."
}
```

#### 2. Generate Proof

**POST** `/generate-proof`

Creates a zero-knowledge proof of identity.

```bash
curl -X POST http://localhost:8080/generate-proof \
  -H "Content-Type: application/json" \
  -d '{
    "secret_hex": "0x1234...",
    "commitment": "123456789..."
  }'
```

**Response:**
```json
{
  "proof": {
    "a": ["0x...", "0x..."],
    "b": [["0x...", "0x..."], ["0x...", "0x..."]],
    "c": ["0x...", "0x..."]
  }
}
```

#### 3. Verify Proof

**POST** `/verify-proof`

Validates a zero-knowledge proof.

```bash
curl -X POST http://localhost:8080/verify-proof \
  -H "Content-Type: application/json" \
  -d '{
    "commitment": "123456789...",
    "proof": {
      "a": ["0x...", "0x..."],
      "b": [["0x...", "0x..."], ["0x...", "0x..."]],
      "c": ["0x...", "0x..."]
    }
  }'
```

**Response:**
```json
{
  "valid": true
}
```

## 📊 Benchmarking

The project includes comprehensive benchmarking tools to measure performance under various load conditions.

### Node.js Benchmark

The main benchmark script (`bench-mark/bench.js`) provides detailed performance analysis:

```bash
# Ensure the server is running
cargo run --release &

# Run the benchmark
node bench-mark/bench.js
```

**Features:**
- Tests all three endpoints (`/register`, `/generate-proof`, `/verify-proof`)
- Multiple concurrency levels (1, 10, 15, 20, 25, 30)
- CPU and memory monitoring
- Latency percentiles and throughput metrics
- 15-second test duration per configuration

**Sample Output:**
```
====================== Benchmark results schema ======================

register  (concurrency 10)
  Avg latency  : 25.43 ms
  P50 latency  : 23.12 ms
  Throughput   : 2.45 MB/s
  Requests/sec : 387.23
  CPU (avg)    : 45.67 %
  Memory (avg) : 156.78 MB

generateProof  (concurrency 10)
  Avg latency  : 145.67 ms
  P50 latency  : 142.33 ms
  Throughput   : 1.23 MB/s
  Requests/sec : 67.89
  CPU (avg)    : 78.45 %
  Memory (avg) : 245.12 MB
```

## 🔬 Technical Details

### Zero-Knowledge Circuit

The core ZK circuit (`circuits/secret-proof.circom`) is elegantly simple:

```circom
template SecretProof() {
    signal input  secret;        // private
    signal input  commitment;    // public

    component h = Poseidon(1);
    h.inputs[0] <== secret;
    h.out === commitment;
}
```

This circuit proves knowledge of a `secret` such that `Poseidon(secret) = commitment` without revealing the secret.

### Cryptographic Components

1. **Keccak256**: Used for hashing user data (email, name)
2. **Poseidon**: ZK-friendly hash function for commitments and secrets
3. **BN254**: Elliptic curve for Groth16 proofs
4. **Groth16**: zk-SNARK proving system

### Scaling Considerations

- Proof generation is CPU-intensive and benefits from multiple cores
- Memory usage scales with concurrent proof generation
- Consider horizontal scaling for high-throughput deployments
- Pre-computed keys and cached hashers provide excellent single-node performance

## 🛠️ Development

### Project Structure

```
zk-auth-gpy/
├── src/
│   └── main.rs              # Main Rust application (optimized)
├── circuits/
│   ├── secret-proof.circom  # ZK circuit definition
│   └── secret-proof/        # Compiled circuit artifacts
├── bench-mark/
│   └── bench.js            # Node.js benchmark script
├── Cargo.toml              # Rust dependencies
└── package.json            # Node.js dependencies
```

### Key Dependencies

**Rust:**
- `actix-web`: High-performance web framework
- `ark-*`: Algebraic cryptography libraries (BN254, Groth16, Circom)
- `light-poseidon`: Optimized Poseidon hash implementation
- `rand`: Fast random number generation with SmallRng support
- `once_cell`: Static initialization for cached resources

**Node.js:**
- `autocannon`: HTTP benchmarking tool
- `axios`: HTTP client for API testing
- `pidusage`: Process monitoring utilities


## 🔧 Configuration

### Environment Variables

```bash
# Server configuration
export RUST_LOG=info           # Logging level
export SERVER_HOST=0.0.0.0     # Bind address
export SERVER_PORT=8080        # Bind port

# Benchmark configuration
export BASE_URL=http://localhost:8080  # Target server URL
```

### Circuit Configuration

Circuit artifacts are included and located in `circuits/secret-proof/`:
- `secret-proof.wasm`: WebAssembly witness generator
- `secret-proof.r1cs`: R1CS constraint system
- `secret_final.zkey`: Groth16 proving/verifying keys

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Run the test suite
6. Submit a pull request

## 📄 License

This project is licensed under the ISC License.

## 🔍 Research Context

This project demonstrates practical applications of zero-knowledge proofs in authentication systems with a focus on performance optimization. It showcases how careful implementation can achieve production-ready performance while maintaining cryptographic security.

### Academic References

- Groth16: "On the Size of Pairing-based Non-interactive Arguments" by Jens Groth
- Poseidon: "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems"
- Circom: Domain-specific language for arithmetic circuits

---

**⚡ Optimized for Performance, Designed for Privacy, Powered by Zero-Knowledge Proofs**
