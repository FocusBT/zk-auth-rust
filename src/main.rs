
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use ark_bn254::{Bn254, Fr, Fq, Fq2, G1Affine, G2Affine};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof, prepare_verifying_key};
use ark_snark::SNARK;
use hex::encode as hex_encode;
use num_bigint::{BigInt, BigUint, Sign};
use once_cell::sync::Lazy;
use rand::RngCore;
use rand::thread_rng;

use rand::rngs::SmallRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use light_poseidon::{Poseidon, PoseidonHasher};         
use std::{fs::File, io::BufReader, path::PathBuf};
use std::sync::{Mutex};
use tokio::sync::Semaphore;

//--------------------------------------------------------------------
// Static artefacts
//--------------------------------------------------------------------
static CIRCUIT_PATH: Lazy<(PathBuf, PathBuf, PathBuf)> = Lazy::new(|| {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("circuits/secret-proof");
    (
        root.join("secret-proof_js/secret-proof.wasm"),
        root.join("secret-proof.r1cs"),
        root.join("secret_final.zkey"),
    )
});

static PROVING_KEY: Lazy<ProvingKey<Bn254>> = Lazy::new(|| {
    let (_, _, zkey) = &*CIRCUIT_PATH;
    let mut rd = BufReader::new(File::open(zkey).expect("proving key missing"));
    read_zkey(&mut rd).expect("invalid zkey").0
});
static VERIFYING_KEY: Lazy<VerifyingKey<Bn254>> = Lazy::new(|| {
    let (_, _, zkey) = &*CIRCUIT_PATH;
    let mut rd = BufReader::new(File::open(zkey).expect("vk missing"));
    let (pk, _) = read_zkey(&mut rd).expect("invalid zkey");
    pk.vk.clone()
});

use ark_groth16::PreparedVerifyingKey;
static PROC_VERIFY_KEY: Lazy<PreparedVerifyingKey<Bn254>> = Lazy::new(|| {
    prepare_verifying_key(&*VERIFYING_KEY)
});

static PROOF_SEM: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(4));

//--------------------------------------------------------------------
// DTOs (unchanged)
//--------------------------------------------------------------------
#[derive(Deserialize)]  struct RegisterRequest { email:String, name:String, age:u32, country:String, dob:String }
#[derive(Serialize)]    struct RegisterResponse { secret:String, nonce:String, commitment:String }
#[derive(Deserialize)]  struct ProofRequest { secret_hex:String, commitment:String }
#[derive(Serialize,Deserialize)] struct ProofJson { a:[String;2], b:[[String;2];2], c:[String;2] }
#[derive(Serialize)]    struct ProofResponse { proof:ProofJson }
#[derive(Deserialize)]  struct VerifyRequest { commitment:String, proof:ProofJson }
#[derive(Serialize)]    struct VerifyResponse { valid:bool }

//--------------------------------------------------------------------
// Poseidon Hashers
//--------------------------------------------------------------------
/// Poseidon hashers keyed by input length.  Creating a Poseidon instance
/// involves computing constants and s‑box parameters; reusing them
/// eliminates that overhead on every call.  The hasher objects are
/// wrapped in `Arc` because `Poseidon` is not `Copy` and cloning it
/// performs a cheap reference count increase.
// Poseidon hashers keyed by input length.  The hash method on Poseidon
// requires a mutable reference.  We wrap each hasher in a Mutex to allow
// mutable access even though the static is immutable.  Using a Mutex here is
// acceptable because hashing is extremely fast relative to the cost of
// acquiring a lock.
static POSEIDON_1: Lazy<Mutex<Poseidon<Fr>>> = Lazy::new(|| {
    Mutex::new(Poseidon::<Fr>::new_circom(1).expect("poseidon init"))
});
static POSEIDON_2: Lazy<Mutex<Poseidon<Fr>>> = Lazy::new(|| {
    Mutex::new(Poseidon::<Fr>::new_circom(2).expect("poseidon init"))
});
static POSEIDON_5: Lazy<Mutex<Poseidon<Fr>>> = Lazy::new(|| {
    Mutex::new(Poseidon::<Fr>::new_circom(5).expect("poseidon init"))
});

//--------------------------------------------------------------------
// Helpers 
//--------------------------------------------------------------------
fn country_u16(code:&str)->u16{let b=code.as_bytes();((b.get(0).copied().unwrap_or(0)as u16)<<8)|(b.get(1).copied().unwrap_or(0)as u16)}

/// Compute Poseidon hash using a cached hasher based on the number of inputs.
fn poseidon_hash(inputs:&[Fr])->Fr {
    match inputs.len() {
        1 => {
            let mut h = POSEIDON_1.lock().unwrap();
            h.hash(inputs).expect("poseidon hash")
        }
        2 => {
            let mut h = POSEIDON_2.lock().unwrap();
            h.hash(inputs).expect("poseidon hash")
        }
        5 => {
            let mut h = POSEIDON_5.lock().unwrap();
            h.hash(inputs).expect("poseidon hash")
        }
        _ => Poseidon::<Fr>::new_circom(inputs.len()).unwrap().hash(inputs).unwrap(),
    }
}

fn fq_to_hex(f:&Fq)->String{let mut bytes=f.into_bigint().to_bytes_be();if bytes.len()<32{bytes=[vec![0u8;32-bytes.len()],bytes].concat();}format!("0x{}",hex_encode(bytes))}
fn fq2_to_hex(f2:&Fq2)->(String,String){(fq_to_hex(&f2.c0),fq_to_hex(&f2.c1))}
fn g1_to_hex(p:&G1Affine)->(String,String){(fq_to_hex(&p.x),fq_to_hex(&p.y))}
fn g2_to_hex(p:&G2Affine)->(String,String,String,String){let(x0,x1)=fq2_to_hex(&p.x);let(y0,y1)=fq2_to_hex(&p.y);(x1,x0,y1,y0)}
fn fq_from_hex(h:&str)->Fq{let mut bytes=hex::decode(h.trim_start_matches("0x")).unwrap();if bytes.len()<32{bytes=[vec![0u8;32-bytes.len()],bytes].concat();}Fq::from_be_bytes_mod_order(&bytes)}

//--------------------------------------------------------------------
// /register
//--------------------------------------------------------------------
#[post("/register")]
async fn register(body:web::Json<RegisterRequest>)->impl Responder{
    // Compute keccak hashes of email and name; convert to field elements.
    let mut k=Keccak256::new();k.update(body.email.to_lowercase());let email_hash=Fr::from_be_bytes_mod_order(&k.finalize());
    let mut k=Keccak256::new();k.update(body.name.trim());let name_hash=Fr::from_be_bytes_mod_order(&k.finalize());

    let age_fe=Fr::from(body.age as u64);
    let country_fe=Fr::from(country_u16(&body.country) as u64);
    let dob_fe=Fr::from(body.dob.replace('-',"").parse::<u64>().unwrap_or(0));

    let user_hash=poseidon_hash(&[email_hash,name_hash,age_fe,country_fe,dob_fe]);

    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);
    let nonce_fe=Fr::from_be_bytes_mod_order(&{let mut pad=[0u8;32];pad[16..].copy_from_slice(&nonce);pad});

    let secret_fe=poseidon_hash(&[user_hash,nonce_fe]);
    let commitment_fe=poseidon_hash(&[secret_fe]);

    let secret_hex={let mut b=secret_fe.into_bigint().to_bytes_be();if b.len()<32{b=[vec![0u8;32-b.len()],b].concat();}format!("0x{}",hex_encode(b))};
    let nonce_hex=format!("0x{}",hex_encode(nonce));
    let commitment_dec=BigUint::from_bytes_be(&commitment_fe.into_bigint().to_bytes_be()).to_string();

    HttpResponse::Ok().json(RegisterResponse{secret:secret_hex,nonce:nonce_hex,commitment:commitment_dec})
}

//--------------------------------------------------------------------
// /generate-proof 
//--------------------------------------------------------------------
#[post("/generate-proof")]
async fn generate_proof(body: web::Json<ProofRequest>) -> impl Responder {
    // ---------- Parse inputs (cheap) ----------
    let secret_fe = {
        let bytes = hex::decode(body.secret_hex.trim_start_matches("0x")).unwrap();
        Fr::from_be_bytes_mod_order(&{
            let mut pad = [0u8; 32];
            pad[32 - bytes.len()..].copy_from_slice(&bytes);
            pad
        })
    };
    let commitment_fe = {
        let dec = BigUint::parse_bytes(body.commitment.as_bytes(), 10).unwrap();
        Fr::from_be_bytes_mod_order(&{
            let mut b = dec.to_bytes_be();
            if b.len() < 32 { b = [vec![0u8; 32 - b.len()], b].concat(); }
            b
        })
    };

    // ---------- Heavy work under semaphore ----------
    let permit = PROOF_SEM.acquire().await.unwrap();
    let secret_input = BigInt::from_bytes_be(Sign::Plus, &secret_fe.into_bigint().to_bytes_be());
    let commit_input = BigInt::from_bytes_be(Sign::Plus, &commitment_fe.into_bigint().to_bytes_be());
    let handle = tokio::task::spawn_blocking(move || {

        let (wasm, r1cs, _) = &*CIRCUIT_PATH;
        let cfg = CircomConfig::<Fr>::new(wasm, r1cs).expect("cannot read circuit artefacts");
        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("secret", secret_input);
        builder.push_input("commitment", commit_input);
        let circuit = builder.build().expect("witness");

        // 2. prove using a fast RNG
        let mut rng = thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::prove(&*PROVING_KEY, circuit, &mut rng)
        .expect("proving failed");

        // 3. serialise proof into JSON strings (do heavy EC->hex in this thread)
        let (a_x, a_y)               = g1_to_hex(&proof.a);
        let (b_x1, b_x0, b_y1, b_y0) = g2_to_hex(&proof.b);
        let (c_x, c_y)               = g1_to_hex(&proof.c);
        ProofJson { a: [a_x, a_y], b: [[b_x1, b_x0], [b_y1, b_y0]], c: [c_x, c_y] }
    });
    let proof_json = handle.await.expect("join");
    drop(permit);

    HttpResponse::Ok().json(ProofResponse { proof: proof_json })
}

//--------------------------------------------------------------------
// /verify-proof
//--------------------------------------------------------------------
#[post("/verify-proof")]
async fn verify_proof(body:web::Json<VerifyRequest>)->impl Responder{
    let a=G1Affine::new(fq_from_hex(&body.proof.a[0]),fq_from_hex(&body.proof.a[1]));
    let b=G2Affine::new(Fq2::new(fq_from_hex(&body.proof.b[0][1]),fq_from_hex(&body.proof.b[0][0])),
                        Fq2::new(fq_from_hex(&body.proof.b[1][1]),fq_from_hex(&body.proof.b[1][0])));
    let c=G1Affine::new(fq_from_hex(&body.proof.c[0]),fq_from_hex(&body.proof.c[1]));
    let proof_ark=Proof{a,b,c};

    let commitment_f={let dec=BigUint::parse_bytes(body.commitment.as_bytes(),10).unwrap();
                      Fr::from_be_bytes_mod_order(&{let mut b=dec.to_bytes_be();if b.len()<32{b=[vec![0u8;32-b.len()],b].concat();}b})};

    // use pre‑computed processed verifying key
    let ok=Groth16::<Bn254,CircomReduction>::verify_with_processed_vk(
              &*PROC_VERIFY_KEY,&[commitment_f],&proof_ark).unwrap_or(false);

    if ok {HttpResponse::Ok().json(VerifyResponse{valid:true})}
    else  {HttpResponse::Unauthorized().json(VerifyResponse{valid:false})}
}

//--------------------------------------------------------------------
// main
//--------------------------------------------------------------------
#[actix_web::main]
async fn main()->std::io::Result<()>{
    println!("🔒 Optimised ZK‑Auth API listening on http://localhost:8080");
    HttpServer::new(||App::new()
        .service(register)
        .service(generate_proof)
        .service(verify_proof))
        .bind(("0.0.0.0",8080))?
        .run()
        .await
}