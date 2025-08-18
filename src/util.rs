use axum::{
  extract::FromRequestParts,
  http::{StatusCode, header, request::Parts},
  response::{IntoResponse, Response},
};
use base64::Engine as _;
use openidconnect::{
  Client, EmptyAdditionalClaims, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet,
  EndpointSet, IdToken, IdTokenFields, NonceVerifier, StandardErrorResponse, StandardTokenResponse,
  core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreRevocableToken,
    CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
  },
};
use password_auth::VerifyError;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBasic(pub String, pub Option<String>);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthBasicRejection {
  Missing,
  InvalidCharacters,
  InvalidEncoding,
  NotBasic,
}

impl IntoResponse for AuthBasicRejection {
  fn into_response(self) -> Response {
    let msg = match self {
      Self::Missing => "`Authorization` header is missing",
      Self::InvalidCharacters => "`Authorization` header contains invalid characters",
      Self::InvalidEncoding => "`Authorization` header could not be decoded",
      Self::NotBasic => "`Authorization` header must be for basic authentication",
    };
    (StatusCode::BAD_REQUEST, msg).into_response()
  }
}

impl AuthBasic {
  fn from_content(contents: &str) -> Result<Self, AuthBasicRejection> {
    let decoded = base64::engine::general_purpose::STANDARD
      .decode(contents)
      .map_err(|_| AuthBasicRejection::InvalidEncoding)?;
    let decoded = String::from_utf8(decoded).map_err(|_| AuthBasicRejection::InvalidCharacters)?;

    // Return depending on if password is present
    Ok(if let Some((id, password)) = decoded.split_once(':') {
      Self(id.to_owned(), Some(password.to_owned()))
    } else {
      Self(decoded, None)
    })
  }
}

impl<B> FromRequestParts<B> for AuthBasic
where
  B: Send + Sync,
{
  type Rejection = AuthBasicRejection;

  async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
    let authorization = parts
      .headers
      .get(header::AUTHORIZATION)
      .ok_or(AuthBasicRejection::Missing)?
      .to_str()
      .map_err(|_| AuthBasicRejection::InvalidCharacters)?;

    // Check that its well-formed basic auth then decode and return
    let split = authorization.split_once(' ');
    match split {
      Some(("Basic", contents)) => Self::from_content(contents),
      _ => Err(AuthBasicRejection::NotBasic),
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthBearer(pub String);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthBearerRejection {
  Missing,
  InvalidCharacters,
  NotBearer,
}

impl IntoResponse for AuthBearerRejection {
  fn into_response(self) -> Response {
    let msg = match self {
      Self::Missing => "`Authorization` header is missing",
      Self::InvalidCharacters => "`Authorization` header contains invalid characters",
      Self::NotBearer => "`Authorization` header must be for bearer authentication",
    };
    (StatusCode::BAD_REQUEST, msg).into_response()
  }
}

impl AuthBearer {
  fn from_content(contents: &str) -> Self {
    Self(contents.to_owned())
  }
}

impl<B> FromRequestParts<B> for AuthBearer
where
  B: Send + Sync,
{
  type Rejection = AuthBearerRejection;

  async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
    let authorization = parts
      .headers
      .get(header::AUTHORIZATION)
      .ok_or(AuthBearerRejection::Missing)?
      .to_str()
      .map_err(|_| AuthBearerRejection::InvalidCharacters)?;

    // Check that its well-formed basic auth then decode and return
    let split = authorization.split_once(' ');
    match split {
      Some(("Bearer", contents)) => Ok(Self::from_content(contents)),
      _ => Err(AuthBearerRejection::NotBearer),
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Auth {
  Basic(AuthBasic),
  Bearer(AuthBearer),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthRejection {
  Missing,
  InvalidCharacters,
  InvalidEncoding,
  NotSupported,
}

impl IntoResponse for AuthRejection {
  fn into_response(self) -> Response {
    let msg = match self {
      Self::Missing => "`Authorization` header is missing",
      Self::InvalidCharacters => "`Authorization` header contains invalid characters",
      Self::InvalidEncoding => "`Authorization` header could not be decoded",
      Self::NotSupported => "`Authorization` header has a unsupported schema",
    };
    (StatusCode::BAD_REQUEST, msg).into_response()
  }
}

impl From<AuthBasicRejection> for AuthRejection {
  fn from(value: AuthBasicRejection) -> Self {
    match value {
      AuthBasicRejection::Missing => Self::Missing,
      AuthBasicRejection::InvalidCharacters => Self::InvalidCharacters,
      AuthBasicRejection::InvalidEncoding => Self::InvalidEncoding,
      AuthBasicRejection::NotBasic => Self::NotSupported,
    }
  }
}

impl From<AuthBearerRejection> for AuthRejection {
  fn from(value: AuthBearerRejection) -> Self {
    match value {
      AuthBearerRejection::Missing => Self::Missing,
      AuthBearerRejection::InvalidCharacters => Self::InvalidCharacters,
      AuthBearerRejection::NotBearer => Self::NotSupported,
    }
  }
}

impl<B> FromRequestParts<B> for Auth
where
  B: Send + Sync,
{
  type Rejection = AuthRejection;

  async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
    let authorization = parts
      .headers
      .get(header::AUTHORIZATION)
      .ok_or(AuthRejection::Missing)?
      .to_str()
      .map_err(|_| AuthRejection::InvalidCharacters)?;

    let split = authorization.split_once(' ');
    Ok(match split {
      Some(("Basic", contents)) => Self::Basic(AuthBasic::from_content(contents)?),
      Some(("Bearer", contents)) => Self::Bearer(AuthBearer::from_content(contents)),
      _ => return Err(AuthRejection::NotSupported),
    })
  }
}

pub fn verify_password(password: impl AsRef<[u8]>, hash: &str) -> Result<(), VerifyError> {
  let password = password.as_ref();
  hash.strip_prefix("$plain$").map_or_else(
    || password_auth::verify_password(password, hash),
    |plain| {
      if password == plain.as_bytes() {
        Ok(())
      } else {
        Err(VerifyError::PasswordInvalid)
      }
    },
  )
}

pub type OidcClient<
  AdditionalClaims = EmptyAdditionalClaims,
  HasAuthUrl = EndpointSet,
  HasDeviceAuthUrl = EndpointNotSet,
  HasIntrospectionUrl = EndpointNotSet,
  HasRevocationUrl = EndpointNotSet,
  HasTokenUrl = EndpointMaybeSet,
  HasUserInfoUrl = EndpointMaybeSet,
> = Client<
  AdditionalClaims,
  CoreAuthDisplay,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJsonWebKey,
  CoreAuthPrompt,
  StandardErrorResponse<CoreErrorResponseType>,
  OidcTokenResponse<AdditionalClaims>,
  CoreTokenIntrospectionResponse,
  CoreRevocableToken,
  CoreRevocationErrorResponse,
  HasAuthUrl,
  HasDeviceAuthUrl,
  HasIntrospectionUrl,
  HasRevocationUrl,
  HasTokenUrl,
  HasUserInfoUrl,
>;

type OidcTokenResponse<AdditionalClaims> =
  StandardTokenResponse<OidcIdTokenFields<AdditionalClaims>, CoreTokenType>;

type OidcIdTokenFields<AdditionalClaims> = IdTokenFields<
  AdditionalClaims,
  EmptyExtraTokenFields,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm,
>;

pub type AccessToken = IdToken<
  EmptyAdditionalClaims,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJwsSigningAlgorithm,
>;

#[derive(Debug)]
pub struct Ignore;

impl NonceVerifier for Ignore {
  fn verify(self, _nonce: Option<&openidconnect::Nonce>) -> Result<(), String> {
    Ok(())
  }
}
