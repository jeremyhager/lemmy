use crate::{context::LemmyContext, sensitive::Sensitive};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use lemmy_db_schema::{
  newtypes::LocalUserId,
  source::login_token::{LoginToken, LoginTokenCreateForm},
};
use lemmy_utils::error::{LemmyErrorExt, LemmyErrorType, LemmyResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
  /// local_user_id, standard claim by RFC 7519.
  pub sub: i32,
  pub iss: String,
  /// Time when this token was issued as UNIX-timestamp in seconds
  pub iat: i64,
}

impl Claims {
  pub async fn validate(jwt: &str, context: &LemmyContext) -> LemmyResult<TokenData<Claims>> {
    // TODO: check db
    let mut validation = Validation::default();
    validation.validate_exp = false;
    validation.required_spec_claims.remove("exp");
    let jwt_secret = &context.secret().jwt_secret;
    let key = DecodingKey::from_secret(jwt_secret.as_ref());
    let claims =
      decode::<Claims>(jwt, &key, &validation).with_lemmy_type(LemmyErrorType::NotLoggedIn)?;
    let is_valid =
      LoginToken::validate(&mut context.pool(), LocalUserId(claims.claims.sub), jwt).await?;
    if !is_valid {
      return Err(LemmyErrorType::NotLoggedIn)?;
    }
    Ok(claims)
  }

  pub async fn generate(
    user_id: LocalUserId,
    context: &LemmyContext,
  ) -> LemmyResult<Sensitive<String>> {
    let hostname = context.settings().hostname.clone();
    let my_claims = Claims {
      sub: user_id.0,
      iss: hostname,
      iat: Utc::now().timestamp(),
    };

    let secret = &context.secret().jwt_secret;
    let key = EncodingKey::from_secret(secret.as_ref());
    let token = encode(&Header::default(), &my_claims, &key)?;
    let form = LoginTokenCreateForm {
      token: token.clone(),
      user_id,
    };
    LoginToken::create(&mut context.pool(), form).await?;
    Ok(Sensitive::new(token))
  }
}
