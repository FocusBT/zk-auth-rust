use actix_web::{post, web, App, HttpResponse, HttpServer, Responder, dev::Server}; // Import Server
use ark_bn254::{Bn254, Fr, Fq, Fq2, G1Affine, G2Affine};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof, prepare_verifying_key};
use ark_snark::SNARK;
use hex::encode as hex_encode;
use num_bigint::{BigInt, BigUint, Sign};
use once_cell::sync::Lazy;
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use light_poseidon::{Poseidon, PoseidonHasher};
use std::{fs::File, io::BufReader, path::PathBuf, net::TcpListener};
use tokio::sync::Semaphore;
use num_cpus;
use gnark_bn254_verifier::{verify as gnark_verify, Fr as GnarkFr, ProvingSystem};
use std::io::Read;
//--------------------------------------------------------------------
// Static artefacts (unchanged)
//--------------------------------------------------------------------
static GNARK_VERIFYING_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut file = File::open("gnark_vk.bin").expect("gnark_vk.bin not found. Please generate it and place it in the project root.");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read gnark_vk.bin");
    buffer
});

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

static PROOF_SEM: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(num_cpus::get()));

//--------------------------------------------------------------------
// DTOs (unchanged)
//--------------------------------------------------------------------
#[derive(Deserialize, Serialize)]
pub struct GnarkVerifyRequest {
    /// The proof, encoded as a hex string
    pub proof_hex: String,
    /// The public inputs, each encoded as a hex string
    pub public_inputs_hex: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterRequest { email:String, name:String, age:u32, country:String, dob:String }
#[derive(Deserialize, Serialize)]
pub struct RegisterResponse { secret:String, nonce:String, commitment:String }
#[derive(Deserialize, Serialize)]
pub struct ProofRequest { secret_hex:String, commitment:String }
#[derive(Serialize,Deserialize, Clone)]
pub struct ProofJson { a:[String;2], b:[[String;2];2], c:[String;2] }
#[derive(Deserialize, Serialize)]
pub struct ProofResponse { proof:ProofJson}
#[derive(Deserialize, Serialize)]
pub struct VerifyRequest { commitment:String, proof:ProofJson }
#[derive(Deserialize, Serialize)]
pub struct VerifyResponse { valid:bool }

//--------------------------------------------------------------------
// Helpers (unchanged)
//--------------------------------------------------------------------
fn country_u16(code:&str)->u16{let b=code.as_bytes();((b.get(0).copied().unwrap_or(0)as u16)<<8)|(b.get(1).copied().unwrap_or(0)as u16)}
fn poseidon_hash(inputs:&[Fr])->Fr{Poseidon::<Fr>::new_circom(inputs.len()).unwrap().hash(inputs).unwrap()}
fn fq_to_hex(f:&Fq)->String{let mut bytes=f.into_bigint().to_bytes_be();if bytes.len()<32{bytes=[vec![0u8;32-bytes.len()],bytes].concat();}format!("0x{}",hex_encode(bytes))}
fn fq2_to_hex(f2:&Fq2)->(String,String){(fq_to_hex(&f2.c0),fq_to_hex(&f2.c1))}
fn g1_to_hex(p:&G1Affine)->(String,String){(fq_to_hex(&p.x),fq_to_hex(&p.y))}
fn g2_to_hex(p:&G2Affine)->(String,String,String,String){let(x0,x1)=fq2_to_hex(&p.x);let(y0,y1)=fq2_to_hex(&p.y);(x1,x0,y1,y0)}
fn fq_from_hex(h:&str)->Fq{let mut bytes=hex::decode(h.trim_start_matches("0x")).unwrap();if bytes.len()<32{bytes=[vec![0u8;32-bytes.len()],bytes].concat();}Fq::from_be_bytes_mod_order(&bytes)}

fn gnark_fr_from_hex(h: &str) -> GnarkFr {
    // 1. Decode hex to bytes
    let bytes = hex::decode(h.trim_start_matches("0x")).unwrap();

    // 2. Convert bytes to a BigUint
    let big_uint = BigUint::from_bytes_be(&bytes);

    // 3. Convert the BigUint into a GnarkFr.
    //    This `From<BigUint>` trait is stable across `ark-ff` versions.
    GnarkFr::from(big_uint)
}
//--------------------------------------------------------------------
// Handlers (unchanged)
//--------------------------------------------------------------------
#[post("/register")]
pub async fn register(body:web::Json<RegisterRequest>)->impl Responder{
    let mut k=Keccak256::new();k.update(body.email.to_lowercase());let email_hash=Fr::from_be_bytes_mod_order(&k.finalize());
    let mut k=Keccak256::new();k.update(body.name.trim());let name_hash=Fr::from_be_bytes_mod_order(&k.finalize());
    let age_fe=Fr::from(body.age as u64);
    let country_fe=Fr::from(country_u16(&body.country) as u64);
    let dob_fe=Fr::from(body.dob.replace('-',"").parse::<u64>().unwrap_or(0));
    let user_hash=poseidon_hash(&[email_hash,name_hash,age_fe,country_fe,dob_fe]);
    let mut nonce=[0u8;16];thread_rng().fill_bytes(&mut nonce);
    let nonce_fe=Fr::from_be_bytes_mod_order(&{let mut pad=[0u8;32];pad[16..].copy_from_slice(&nonce);pad});
    let secret_fe=poseidon_hash(&[user_hash,nonce_fe]);
    let commitment_fe=poseidon_hash(&[secret_fe]);
    let secret_hex={let mut b=secret_fe.into_bigint().to_bytes_be();if b.len()<32{b=[vec![0u8;32-b.len()],b].concat();}format!("0x{}",hex_encode(b))};
    let nonce_hex=format!("0x{}",hex_encode(nonce));
    let commitment_dec=BigUint::from_bytes_be(&commitment_fe.into_bigint().to_bytes_be()).to_string();
    HttpResponse::Ok().json(RegisterResponse{secret:secret_hex,nonce:nonce_hex,commitment:commitment_dec})
}

#[post("/proof")]
pub async fn proof(body: web::Json<ProofRequest>) -> impl Responder {
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
    let permit = PROOF_SEM.acquire().await.unwrap();
    let (proof, _) = tokio::task::spawn_blocking(move || {
        let (wasm, r1cs, _) = &*CIRCUIT_PATH;
        let cfg = CircomConfig::<Fr>::new(wasm, r1cs)
            .expect("cannot read circuit artefacts");
        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("secret",
            BigInt::from_bytes_be(Sign::Plus, &secret_fe.into_bigint().to_bytes_be()));
        builder.push_input("commitment",
            BigInt::from_bytes_be(Sign::Plus, &commitment_fe.into_bigint().to_bytes_be()));
        let circuit = builder.build().expect("witness");
        let mut rng = thread_rng();
        let proof = Groth16::<Bn254, CircomReduction>::prove(&*PROVING_KEY, circuit, &mut rng)
            .expect("proving failed");
        let commitment_hex = format!("0x{}",
            BigUint::parse_bytes(body.commitment.as_bytes(), 10).unwrap().to_str_radix(16));
        (proof, commitment_hex)
    }).await.expect("join");
    drop(permit);
    let (a_x, a_y) = g1_to_hex(&proof.a);
    let (b_x1, b_x0, b_y1, b_y0) = g2_to_hex(&proof.b);
    let (c_x, c_y) = g1_to_hex(&proof.c);
    HttpResponse::Ok().json(ProofResponse {
        proof: ProofJson { a: [a_x.clone(), a_y.clone()],
                           b: [[b_x1.clone(), b_x0.clone()], [b_y1.clone(), b_y0.clone()]],
                           c: [c_x.clone(), c_y.clone()] }
    })
}

#[post("/verify-gnark")]
pub async fn verify_gnark(body: web::Json<GnarkVerifyRequest>) -> impl Responder {
    // 1. Decode the proof from hex to bytes
    let proof_bytes = match hex::decode(body.proof_hex.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        Err(_) => return HttpResponse::BadRequest().json(VerifyResponse { valid: false }),
    };

    // 2. Decode the public inputs from hex strings to Field Elements
    let public_inputs: Vec<GnarkFr> = body
        .public_inputs_hex
        .iter()
        .map(|hex_str| gnark_fr_from_hex(hex_str))
        .collect();

    // 3. Perform the verification using the gnark-rs library
    //    We pass the proof, the statically loaded key, the public inputs,
    //    and specify that we're using the Groth16 proving system.
    let is_valid = gnark_verify(
        &proof_bytes,
        &GNARK_VERIFYING_KEY,
        &public_inputs,
        ProvingSystem::Groth16,
    );

    // 4. Return the response
    if is_valid {
        HttpResponse::Ok().json(VerifyResponse { valid: true })
    } else {
        HttpResponse::Unauthorized().json(VerifyResponse { valid: false })
    }
}


#[post("/verify")]
pub async fn verify(body:web::Json<VerifyRequest>)->impl Responder{
    let a=G1Affine::new(fq_from_hex(&body.proof.a[0]),fq_from_hex(&body.proof.a[1]));
    let b=G2Affine::new(Fq2::new(fq_from_hex(&body.proof.b[0][1]),fq_from_hex(&body.proof.b[0][0])),
                        Fq2::new(fq_from_hex(&body.proof.b[1][1]),fq_from_hex(&body.proof.b[1][0])));
    let c=G1Affine::new(fq_from_hex(&body.proof.c[0]),fq_from_hex(&body.proof.c[1]));
    let proof_ark=Proof{a,b,c};
    let commitment_f={let dec=BigUint::parse_bytes(body.commitment.as_bytes(),10).unwrap();
                      Fr::from_be_bytes_mod_order(&{let mut b=dec.to_bytes_be();if b.len()<32{b=[vec![0u8;32-b.len()],b].concat();}b})};
    let ok=Groth16::<Bn254,CircomReduction>::verify_with_processed_vk(
              &prepare_verifying_key(&*VERIFYING_KEY),&[commitment_f],&proof_ark).unwrap_or(false);
    if ok {HttpResponse::Ok().json(VerifyResponse{valid:true})}
    else  {HttpResponse::Unauthorized().json(VerifyResponse{valid:false})}
}

//--------------------------------------------------------------------
// Application Runner (Updated)
//--------------------------------------------------------------------
// The function is no longer async. It returns a `Server` future that can be awaited.
pub fn run(listener: TcpListener) -> std::io::Result<Server> {
    println!("🔒 ZK-Auth API listening on http://{}", listener.local_addr().unwrap());
    let server = HttpServer::new(|| {
        App::new()
            .service(register)
            .service(proof)
            .service(verify)
            .service(verify_gnark)
    })
    .listen(listener)?
    .run();
    Ok(server)
}
