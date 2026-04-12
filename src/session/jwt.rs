use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::de::DeserializeOwned;

use crate::error::AgentIAMError;
use crate::models::{AccessTokenClaims, SessionTokenClaims};

pub fn sign_access_token(
    claims: &AccessTokenClaims,
    secret: &[u8],
) -> Result<String, AgentIAMError> {
    let token = encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret),
    )?;
    Ok(token)
}

pub fn sign_session_token(
    claims: &SessionTokenClaims,
    secret: &[u8],
) -> Result<String, AgentIAMError> {
    let token = encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret),
    )?;
    Ok(token)
}

pub fn verify_token<T: DeserializeOwned>(
    token: &str,
    secret: &[u8],
) -> Result<TokenData<T>, AgentIAMError> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.validate_aud = false;
    let data = decode::<T>(token, &DecodingKey::from_secret(secret), &validation)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AgentIAMClaims, Budget};
    use chrono::Utc;

    const TEST_SECRET: &[u8] = b"test-secret-key-for-agentiam-jwt";

    fn make_access_claims(exp_offset_secs: i64) -> AccessTokenClaims {
        let now = Utc::now().timestamp();
        AccessTokenClaims {
            iss: "agentiam".to_string(),
            sub: "client-001".to_string(),
            aud: "agentiam".to_string(),
            exp: now + exp_offset_secs,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            scope: "authorize sessions:read".to_string(),
            agentiam: AgentIAMClaims {
                client_id: "client-001".to_string(),
                env: "development".to_string(),
            },
        }
    }

    fn make_session_claims(exp_offset_secs: i64) -> SessionTokenClaims {
        let now = Utc::now().timestamp();
        SessionTokenClaims {
            iss: "agentiam".to_string(),
            sub: r#"AgentIAM::Agent::"research-scout""#.to_string(),
            aud: "agentiam".to_string(),
            exp: now + exp_offset_secs,
            iat: now,
            jti: "sess-001".to_string(),
            delegator: r#"AgentIAM::User::"alice""#.to_string(),
            delegation_chain: vec![r#"AgentIAM::User::"alice""#.to_string()],
            scope: vec![
                r#"AgentIAM::Action::"read""#.to_string(),
                r#"AgentIAM::Action::"list""#.to_string(),
            ],
            budget: Budget {
                max_tokens: 10000,
                max_cost_cents: 5000,
                max_calls: 100,
                used_tokens: 0,
                used_cost_cents: 0,
                used_calls: 0,
            },
            max_chain_depth: 5,
            metadata: None,
        }
    }

    #[test]
    fn test_sign_and_verify_access_token() {
        let claims = make_access_claims(3600);
        let token = sign_access_token(&claims, TEST_SECRET).unwrap();
        let data: TokenData<AccessTokenClaims> = verify_token(&token, TEST_SECRET).unwrap();
        assert_eq!(data.claims.sub, "client-001");
        assert_eq!(data.claims.scope, "authorize sessions:read");
        assert_eq!(data.claims.agentiam.env, "development");
    }

    #[test]
    fn test_sign_and_verify_session_token() {
        let claims = make_session_claims(3600);
        let token = sign_session_token(&claims, TEST_SECRET).unwrap();
        let data: TokenData<SessionTokenClaims> = verify_token(&token, TEST_SECRET).unwrap();
        assert_eq!(data.claims.jti, "sess-001");
        assert_eq!(
            data.claims.delegator,
            r#"AgentIAM::User::"alice""#
        );
        assert_eq!(data.claims.scope.len(), 2);
        assert_eq!(data.claims.max_chain_depth, 5);
    }

    #[test]
    fn test_expired_token_rejected() {
        let claims = make_access_claims(-120); // well past leeway
        let token = sign_access_token(&claims, TEST_SECRET).unwrap();
        let result = verify_token::<AccessTokenClaims>(&token, TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_token_rejected() {
        let claims = make_access_claims(3600);
        let mut token = sign_access_token(&claims, TEST_SECRET).unwrap();
        // Flip a character in the signature part
        let last = token.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        token.push(replacement);
        let result = verify_token::<AccessTokenClaims>(&token, TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let claims = make_access_claims(3600);
        let token = sign_access_token(&claims, TEST_SECRET).unwrap();
        let result = verify_token::<AccessTokenClaims>(&token, b"wrong-secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_session_token_budget_roundtrip() {
        let claims = make_session_claims(3600);
        let token = sign_session_token(&claims, TEST_SECRET).unwrap();
        let data: TokenData<SessionTokenClaims> = verify_token(&token, TEST_SECRET).unwrap();
        assert_eq!(data.claims.budget.max_tokens, 10000);
        assert_eq!(data.claims.budget.used_tokens, 0);
        assert!(!data.claims.budget.is_exhausted());
    }

    #[test]
    fn test_access_token_claims_fields() {
        let claims = make_access_claims(3600);
        let token = sign_access_token(&claims, TEST_SECRET).unwrap();
        let data: TokenData<AccessTokenClaims> = verify_token(&token, TEST_SECRET).unwrap();
        assert_eq!(data.claims.iss, "agentiam");
        assert_eq!(data.claims.aud, "agentiam");
        assert!(data.claims.iat > 0);
        assert!(data.claims.exp > data.claims.iat);
        assert!(!data.claims.jti.is_empty());
    }
}
