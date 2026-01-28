//! Authentication and signature verification tests.
//!
//! Tests for:
//! - `extract_signature` - extracting authentication metadata from requests
//! - `verify_signature_and_get_principal` - verifying signatures and retrieving principals

use super::common::*;
use crate::server::extract_signature;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataValue;
use tonic::Request;
use zopp_storage::*;

// ================== extract_signature tests ==================

#[tokio::test]
async fn extract_signature_valid_metadata() {
    let principal_id = PrincipalId(uuid::Uuid::now_v7());
    let timestamp = Utc::now().timestamp();
    let signature = vec![0u8; 64];
    let request_hash = vec![1u8; 32];

    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(principal_id.0.to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature)).unwrap(),
    );
    request.metadata_mut().insert(
        "request-hash",
        MetadataValue::try_from(hex::encode(&request_hash)).unwrap(),
    );

    let (extracted_pid, extracted_ts, extracted_sig, extracted_hash) =
        extract_signature(&request).unwrap();

    assert_eq!(extracted_pid.0, principal_id.0);
    assert_eq!(extracted_ts, timestamp);
    assert_eq!(extracted_sig, signature);
    assert_eq!(extracted_hash, request_hash);
}

#[tokio::test]
async fn extract_signature_missing_principal_id() {
    let request = Request::new(zopp_proto::Empty {});
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Missing principal-id"));
}

#[tokio::test]
async fn extract_signature_invalid_principal_id_format() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from("not-a-uuid").unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Invalid principal-id"));
}

#[tokio::test]
async fn extract_signature_missing_timestamp() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Missing timestamp"));
}

#[tokio::test]
async fn extract_signature_invalid_timestamp_format() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from("not-a-number").unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid timestamp"));
}

#[tokio::test]
async fn extract_signature_missing_signature() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Missing signature"));
}

#[tokio::test]
async fn extract_signature_invalid_signature_hex() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    request
        .metadata_mut()
        .insert("signature", MetadataValue::try_from("not-hex!").unwrap());
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid signature"));
}

#[tokio::test]
async fn extract_signature_missing_request_hash() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode([0u8; 64])).unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Missing request-hash"));
}

// ================== verify_signature_and_get_principal tests ==================

#[tokio::test]
async fn verify_signature_valid() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};
    let request = create_signed_request(&principal_id, &signing_key, method, request_body);

    // Extract values from request
    let (_, timestamp, signature, request_hash) = extract_signature(&request).unwrap();

    // Verify signature
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            method,
            &request_body,
            &request_hash,
        )
        .await
        .unwrap();

    assert_eq!(principal.id.0, principal_id.0);
}

#[tokio::test]
async fn verify_signature_timestamp_too_old() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    // Create a request with old timestamp
    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let old_timestamp = (Utc::now() - Duration::seconds(120)).timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&old_timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            old_timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("too old"));
}

#[tokio::test]
async fn verify_signature_timestamp_too_future() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let future_timestamp = (Utc::now() + Duration::seconds(120)).timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&future_timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            future_timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("future"));
}

#[tokio::test]
async fn verify_signature_hash_mismatch() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    // Provide wrong hash
    let wrong_hash = vec![0u8; 32];
    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&wrong_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &wrong_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("hash mismatch"));
}

#[tokio::test]
async fn verify_signature_invalid_principal() {
    let server = create_test_server().await;
    let fake_principal_id = PrincipalId(uuid::Uuid::now_v7());
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &fake_principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid principal"));
}

#[tokio::test]
async fn verify_signature_wrong_key() {
    let server = create_test_server().await;
    let (_, principal_id, _) = create_test_user(&server, "test@example.com", "laptop").await;

    // Use a different signing key
    let wrong_signing_key = SigningKey::generate(&mut rand_core::OsRng);

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = wrong_signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid signature"));
}
