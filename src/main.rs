use axum::{
    Router, 
    routing::post, 
    extract::Json, 
    response::Json as ResponseJson, 
    serve,
    http::StatusCode
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer, Signature},
    system_instruction,
};
use spl_token::{
    instruction as token_instruction,
};
use tokio::net::TcpListener;
use std::str::FromStr;
use bs58;
use base64::{Engine as _, engine::general_purpose};

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenData {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

fn error_response<T>(message: &str) -> Result<ResponseJson<ApiResponse<T>>, StatusCode> {
    Ok(ResponseJson(ApiResponse {
        success: false,
        data: None,
        error: Some(message.to_string()),
    }))
}

fn success_response<T>(data: T) -> Result<ResponseJson<ApiResponse<T>>, StatusCode> {
    Ok(ResponseJson(ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    }))
}

async fn generate_keypair() -> Result<ResponseJson<ApiResponse<KeypairData>>, StatusCode> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    
    success_response(KeypairData { pubkey, secret })
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionData>>, StatusCode> {
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid mint authority"),
    };

    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid mint address"),
    };

    let token_program_id = spl_token::id();
    
    let instruction = match token_instruction::initialize_mint(
        &token_program_id,
        &mint_pubkey,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    ) {
        Ok(inst) => inst,
        Err(_) => return error_response("Failed to create mint instruction"),
    };

    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    success_response(InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    })
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionData>>, StatusCode> {
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid mint address"),
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid destination address"),
    };

    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid authority address"),
    };

    let token_program_id = spl_token::id();
    let instruction = match token_instruction::mint_to(
        &token_program_id,
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return error_response("Failed to create mint instruction"),
    };

    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    success_response(InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    })
}

async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<ResponseJson<ApiResponse<SignMessageData>>, StatusCode> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return error_response("Missing required fields");
    }

    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return error_response("Invalid secret key format"),
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return error_response("Invalid secret key"),
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());
    let public_key = bs58::encode(keypair.pubkey().to_bytes()).into_string();

    success_response(SignMessageData {
        signature: signature_b64,
        public_key,
        message: payload.message,
    })
}

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<ResponseJson<ApiResponse<VerifyMessageData>>, StatusCode> {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return error_response("Missing required fields");
    }

    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid public key"),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => return error_response("Invalid signature format"),
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return error_response("Invalid signature"),
    };

    let message_bytes = payload.message.as_bytes();
    let is_valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    success_response(VerifyMessageData {
        valid: is_valid,
        message: payload.message,
        pubkey: payload.pubkey,
    })
}

async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<ResponseJson<ApiResponse<SendSolData>>, StatusCode> {
    let from = match Pubkey::from_str(&payload.from) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid from address"),
    };

    let to = match Pubkey::from_str(&payload.to) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid to address"),
    };

    if payload.lamports == 0 {
        return error_response("Amount must be greater than 0");
    }

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    success_response(SendSolData {
        program_id: instruction.program_id.to_string(),
        accounts: vec![
            from.to_string(),
            to.to_string(),
        ],
        instruction_data,
    })
}

async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<ResponseJson<ApiResponse<SendTokenData>>, StatusCode> {
    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid destination address"),
    };

    let _mint = match Pubkey::from_str(&payload.mint) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid mint address"),
    };

    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(p) => p,
        Err(_) => return error_response("Invalid owner address"),
    };

    if payload.amount == 0 {
        return error_response("Amount must be greater than 0");
    }

    let token_program_id = spl_token::id();
    
    let instruction = match token_instruction::transfer(
        &token_program_id,
        &owner, // source (owner's token account)
        &destination, // destination token account
        &owner, // owner
        &[],
        payload.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return error_response("Failed to create transfer instruction"),
    };

    let accounts = instruction.accounts.iter().map(|acc| TokenAccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    success_response(SendTokenData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running at http://{}", listener.local_addr().unwrap());

    serve(listener, app).await.unwrap();
}
