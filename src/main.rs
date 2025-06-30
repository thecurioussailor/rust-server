use axum::{
    Router, 
    routing::post, 
    extract::Json, 
    response::{Json as ResponseJson, IntoResponse}, 
    serve,
    http::StatusCode,
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
use spl_associated_token_account::get_associated_token_address;
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
    mint_authority: Option<String>,
    mint: Option<String>,
    decimals: Option<i32>,
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
    mint: Option<String>,
    destination: Option<String>,
    authority: Option<String>,
    amount: Option<i64>,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: Option<String>,
    secret: Option<String>,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: Option<String>,
    signature: Option<String>,
    pubkey: Option<String>,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: Option<String>,
    to: Option<String>,
    lamports: Option<i64>,
}

#[derive(Serialize)]
struct SendSolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: Option<String>,
    mint: Option<String>,
    owner: Option<String>,
    amount: Option<i64>,
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

async fn generate_keypair() -> impl IntoResponse {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    
    ResponseJson(ApiResponse {
        success: true,
        data: Some(KeypairData { pubkey, secret }),
        error: None,
    })
}

async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> impl IntoResponse {
    if payload.mint_authority.is_none() || payload.mint.is_none() || payload.decimals.is_none() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let mint_authority_str = payload.mint_authority.unwrap();
    let mint_str = payload.mint.unwrap();
    let decimals = payload.decimals.unwrap();
    
    if mint_authority_str.is_empty() || mint_str.is_empty() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    if decimals < 0 || decimals > 255 {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Invalid decimals value".to_string()),
        })).into_response();
    }

    let mint_authority = match Pubkey::from_str(&mint_authority_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Invalid mint authority".to_string()),
        })).into_response(),
    };

    let mint_pubkey = match Pubkey::from_str(&mint_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Invalid mint address".to_string()),
        })).into_response(),
    };

    let token_program_id = spl_token::id();
    
    let instruction = match token_instruction::initialize_mint(
        &token_program_id,
        &mint_pubkey,
        &mint_authority,
        Some(&mint_authority),
        decimals as u8,
    ) {
        Ok(inst) => inst,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Failed to create mint instruction".to_string()),
        })).into_response(),
    };

    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    ResponseJson(ApiResponse {
        success: true,
        data: Some(InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    }).into_response()
}

async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> impl IntoResponse {
    if payload.mint.is_none() || payload.destination.is_none() || payload.authority.is_none() || payload.amount.is_none() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let mint_str = payload.mint.unwrap();
    let destination_str = payload.destination.unwrap();
    let authority_str = payload.authority.unwrap();
    let amount = payload.amount.unwrap();
    
    if mint_str.is_empty() || destination_str.is_empty() || authority_str.is_empty() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    if amount <= 0 {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        })).into_response();
    }

    let mint = match Pubkey::from_str(&mint_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Invalid mint address".to_string()),
        })).into_response(),
    };

    let destination_wallet = match Pubkey::from_str(&destination_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Invalid destination address".to_string()),
        })).into_response(),
    };

    let authority = match Pubkey::from_str(&authority_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Invalid authority address".to_string()),
        })).into_response(),
    };

    // Derive Associated Token Account for the destination wallet
    let destination_ata = get_associated_token_address(&destination_wallet, &mint);

    let token_program_id = spl_token::id();
    let instruction = match token_instruction::mint_to(
        &token_program_id,
        &mint,
        &destination_ata,
        &authority,
        &[],
        amount as u64,
    ) {
        Ok(inst) => inst,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<InstructionData> {
            success: false,
            data: None,
            error: Some("Failed to create mint instruction".to_string()),
        })).into_response(),
    };

    let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    ResponseJson(ApiResponse {
        success: true,
        data: Some(InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    }).into_response()
}

async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> impl IntoResponse {
    if payload.message.is_none() || payload.secret.is_none() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SignMessageData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let message = payload.message.unwrap();
    let secret = payload.secret.unwrap();
    
    if message.is_empty() || secret.is_empty() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SignMessageData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let secret_bytes = match bs58::decode(&secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SignMessageData> {
            success: false,
            data: None,
            error: Some("Invalid secret key format".to_string()),
        })).into_response(),
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SignMessageData> {
            success: false,
            data: None,
            error: Some("Invalid secret key".to_string()),
        })).into_response(),
    };

    let message_bytes = message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());
    let public_key = bs58::encode(keypair.pubkey().to_bytes()).into_string();

    ResponseJson(ApiResponse {
        success: true,
        data: Some(SignMessageData {
            signature: signature_b64,
            public_key,
            message: message,
        }),
        error: None,
    }).into_response()
}

async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> impl IntoResponse {
    if payload.message.is_none() || payload.signature.is_none() || payload.pubkey.is_none() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<VerifyMessageData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let message = payload.message.unwrap();
    let signature_str = payload.signature.unwrap();
    let pubkey_str = payload.pubkey.unwrap();
    
    if message.is_empty() || signature_str.is_empty() || pubkey_str.is_empty() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<VerifyMessageData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let pubkey = match Pubkey::from_str(&pubkey_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<VerifyMessageData> {
            success: false,
            data: None,
            error: Some("Invalid public key".to_string()),
        })).into_response(),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&signature_str) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<VerifyMessageData> {
            success: false,
            data: None,
            error: Some("Invalid signature format".to_string()),
        })).into_response(),
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<VerifyMessageData> {
            success: false,
            data: None,
            error: Some("Invalid signature".to_string()),
        })).into_response(),
    };

    let message_bytes = message.as_bytes();
    let is_valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    ResponseJson(ApiResponse {
        success: true,
        data: Some(VerifyMessageData {
            valid: is_valid,
            message: message,
            pubkey: pubkey_str,
        }),
        error: None,
    }).into_response()
}

async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> impl IntoResponse {
    if payload.from.is_none() || payload.to.is_none() || payload.lamports.is_none() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendSolData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let from_str = payload.from.unwrap();
    let to_str = payload.to.unwrap();
    let lamports = payload.lamports.unwrap();
    
    if from_str.is_empty() || to_str.is_empty() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendSolData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let from = match Pubkey::from_str(&from_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendSolData> {
            success: false,
            data: None,
            error: Some("Invalid from address".to_string()),
        })).into_response(),
    };

    let to = match Pubkey::from_str(&to_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendSolData> {
            success: false,
            data: None,
            error: Some("Invalid to address".to_string()),
        })).into_response(),
    };

    if lamports <= 0 {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendSolData> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        })).into_response();
    }

    if from == to {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendSolData> {
            success: false,
            data: None,
            error: Some("Cannot transfer to the same address".to_string()),
        })).into_response();
    }

    let invalid_addresses = vec![
        solana_sdk::system_program::id(),
        spl_token::id(),
        solana_sdk::sysvar::rent::id(),
        solana_sdk::sysvar::clock::id(),
        solana_sdk::sysvar::stake_history::id(),
        solana_sdk::sysvar::instructions::id(),
    ];

    for invalid_addr in invalid_addresses {
        if from == invalid_addr || to == invalid_addr {
            return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendSolData> {
                success: false,
                data: None,
                error: Some("Invalid address".to_string()),
            })).into_response();
        }
    }

    if from_str.starts_with("Sysvar") || to_str.starts_with("Sysvar") {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendSolData> {
            success: false,
            data: None,
            error: Some("Invalid address".to_string()),
        })).into_response();
    }

    let instruction = system_instruction::transfer(&from, &to, lamports as u64);
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    ResponseJson(ApiResponse {
        success: true,
        data: Some(SendSolData {
            program_id: instruction.program_id.to_string(),
            accounts: vec![
                from.to_string(),
                to.to_string(),
            ],
            instruction_data,
        }),
        error: None,
    }).into_response()
}

async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> impl IntoResponse {
    if payload.destination.is_none() || payload.mint.is_none() || payload.owner.is_none() || payload.amount.is_none() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendTokenData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let destination_str = payload.destination.unwrap();
    let mint_str = payload.mint.unwrap();
    let owner_str = payload.owner.unwrap();
    let amount = payload.amount.unwrap();
    
    if destination_str.is_empty() || mint_str.is_empty() || owner_str.is_empty() {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendTokenData> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        })).into_response();
    }

    let destination_wallet = match Pubkey::from_str(&destination_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendTokenData> {
            success: false,
            data: None,
            error: Some("Invalid destination address".to_string()),
        })).into_response(),
    };

    let mint = match Pubkey::from_str(&mint_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendTokenData> {
            success: false,
            data: None,
            error: Some("Invalid mint address".to_string()),
        })).into_response(),
    };

    let owner_wallet = match Pubkey::from_str(&owner_str) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendTokenData> {
            success: false,
            data: None,
            error: Some("Invalid owner address".to_string()),
        })).into_response(),
    };

    if amount <= 0 {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendTokenData> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        })).into_response();
    }

    if owner_wallet == destination_wallet {
        return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendTokenData> {
            success: false,
            data: None,
            error: Some("Cannot transfer to the same address".to_string()),
        })).into_response();
    }

    // Derive Associated Token Accounts for both wallets
    let source_token_account = get_associated_token_address(&owner_wallet, &mint);
    let dest_token_account = get_associated_token_address(&destination_wallet, &mint);
    
    let token_program_id = spl_token::id();
    
    let instruction = match token_instruction::transfer(
        &token_program_id,
        &source_token_account,
        &dest_token_account,
        &owner_wallet,
        &[],
        amount as u64,
    ) {
        Ok(inst) => inst,
        Err(_) => return (StatusCode::BAD_REQUEST, ResponseJson(ApiResponse::<SendTokenData> {
            success: false,
            data: None,
            error: Some("Failed to create transfer instruction".to_string()),
        })).into_response(),
    };

    let accounts = instruction.accounts.iter().map(|acc| TokenAccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    ResponseJson(ApiResponse {
        success: true,
        data: Some(SendTokenData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    }).into_response()
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
    println!("Solana HTTP Server running at http://{}", listener.local_addr().unwrap());
    println!("Available endpoints:");
    println!("  POST /keypair");
    println!("  POST /token/create");
    println!("  POST /token/mint");
    println!("  POST /message/sign");
    println!("  POST /message/verify");
    println!("  POST /send/sol");
    println!("  POST /send/token");

    serve(listener, app).await.unwrap();
}
