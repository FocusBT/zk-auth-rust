use actix_web::{App, HttpServer};
use criterion::{criterion_group, criterion_main, Criterion};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::TcpListener;
use std::time::Duration;

// This import will now work correctly.
use zk_auth_api::{register, proof, verify, run, GnarkVerifyRequest}; // Import the new DTO

//--------------------------------------------------------------------
// DTOs (Copied from lib.rs for convenience)
//--------------------------------------------------------------------
#[derive(Deserialize, Debug)]
struct RegisterResponse {
    secret: String,
    nonce: String,
    commitment: String,
}

#[derive(Serialize, Debug)]
struct RegisterRequest<'a> {
    email: &'a str,
    name: &'a str,
    age: u32,
    country: &'a str,
    dob: &'a str,
}

#[derive(Deserialize, Debug)]
struct ProofResponse {
    proof: ProofJson,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProofJson {
    a: [String; 2],
    b: [[String; 2]; 2],
    c: [String; 2],
}

#[derive(Serialize, Debug)]
struct ProofRequest<'a> {
    secret_hex: &'a str,
    commitment: &'a str,
}

#[derive(Serialize, Debug)]
struct VerifyRequest<'a> {
    commitment: &'a str,
    proof: &'a ProofJson,
}

// --- CONSTANTS FOR GNARK BENCHMARK ---
// IMPORTANT: Replace these with a real, valid proof and public input generated from your gnark project.
const VALID_GNARK_PROOF_HEX: &str = "0xcd28488f775e24ba9dd6c1b98ad6f93db613750e7b83a0d28b996f7870123e09c232e9376f7f6af6bbbb3e6d0fa468615a50205dc2682681a3ebe4e3675d1e010fb7cb78f7f3b42bd8bce149828c254d339e9907e50eed51297cd6e90ff5574da7ee3dddfc059500247efe5e9580d625f4c6727f4fb37776490670e12e3c586800000000400000000000000000000000000000000000000000000000000";
const VALID_GNARK_PUBLIC_INPUT_HEX: &str = "0x281eca8d56588630a3f8d32664731f59667267661501fbcc19eb7f823e80155f";


/// The main benchmark function
fn api_benchmark(c: &mut Criterion) {
    // Create the Tokio runtime FIRST.
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Enter the runtime context to spawn the server.
    let server_address = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
        let port = listener.local_addr().unwrap().port();
        let address = format!("http://127.0.0.1:{}", port);

        // run() now returns a Result<Server>.
        let server = run(listener).expect("Failed to create server instance");

        // Spawn the server as a background task inside the runtime.
        tokio::spawn(server);

        address
    });

    let client = Client::new();

    // --- Step 1: Register and get tokens for subsequent tests ---
    let (secret, commitment, proof_json) = rt.block_on(async {
        let register_payload = RegisterRequest {
            email: "test@example.com",
            name: "Test User",
            age: 30,
            country: "IE",
            dob: "19900101",
        };
        let resp = client
            .post(format!("{}/register", server_address))
            .json(&register_payload)
            .send()
            .await
            .expect("Failed to register");
        assert!(resp.status().is_success(), "Register failed");
        let register_response: RegisterResponse = resp.json().await.expect("Failed to parse register response");

        let proof_payload = ProofRequest {
            secret_hex: &register_response.secret,
            commitment: &register_response.commitment,
        };
        let resp = client
            .post(format!("{}/proof", server_address))
            .json(&proof_payload)
            .send()
            .await
            .expect("Failed to get proof");
        assert!(resp.status().is_success(), "Proof generation failed");
        let proof_response: ProofResponse = resp.json().await.expect("Failed to parse proof response");

        (register_response.secret, register_response.commitment, proof_response.proof)
    });

    // --- Benchmark Group ---
    let mut group = c.benchmark_group("ZK Auth API");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(15));

    // Benchmark /register
    group.bench_function("POST /register", |b| {
        b.to_async(&rt).iter(|| async {
            let payload = RegisterRequest {
                email: "test@example.com",
                name: "Test User",
                age: 30,
                country: "IE",
                dob: "19900101",
            };
            let resp = client.post(format!("{}/register", server_address)).json(&payload).send().await.unwrap();
            assert!(resp.status().is_success());
        });
    });

    // Benchmark /proof
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.bench_function("POST /proof", |b| {
        b.to_async(&rt).iter(|| async {
            let payload = ProofRequest {
                secret_hex: &secret,
                commitment: &commitment,
            };
            let resp = client.post(format!("{}/proof", server_address)).json(&payload).send().await.unwrap();
            assert!(resp.status().is_success());
        });
    });

    // Benchmark /verify
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("POST /verify", |b| {
        b.to_async(&rt).iter(|| async {
            let payload = VerifyRequest {
                commitment: &commitment,
                proof: &proof_json,
            };
            let resp = client.post(format!("{}/verify", server_address)).json(&payload).send().await.unwrap();
            assert!(resp.status().is_success());
        });
    });
    
    // --- ADD THIS NEW BENCHMARK FOR GNARK ---
    group.bench_function("POST /verify-gnark", |b| {
        b.to_async(&rt).iter(|| async {
            let payload = GnarkVerifyRequest {
                proof_hex: VALID_GNARK_PROOF_HEX.to_string(),
                public_inputs_hex: vec![VALID_GNARK_PUBLIC_INPUT_HEX.to_string()],
            };
            let resp = client.post(format!("{}/verify-gnark", server_address)).json(&payload).send().await.unwrap();
            // We assert success to make sure our hardcoded proof is actually valid.
            assert!(resp.status().is_success());
        });
    });

    group.finish();
}

// Register the benchmark group
criterion_group!(benches, api_benchmark);
criterion_main!(benches);