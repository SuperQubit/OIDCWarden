use std::{borrow::Cow, sync::LazyLock, time::Duration};

use openidconnect::{
    AccessToken, AdditionalClaims, AuthDisplay, AuthPrompt, AuthenticationFlow, AuthorizationCode,
    AuthorizationRequest, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IdTokenClaims, IdTokenFields, JsonWebKeySet, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RefreshToken, ResponseType, Scope, StandardErrorResponse,
    StandardTokenResponse, UserInfoClaims,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreIdTokenVerifier, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
        CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
    },
    reqwest, url,
};
use regex::Regex;
use serde_json::Value;
use url::Url;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult},
    db::models::SsoAuth,
    sso::{OIDCCode, OIDCCodeChallenge, OIDCCodeVerifier, OIDCState},
};

static CLIENT_CACHE_KEY: LazyLock<String> = LazyLock::new(|| "sso-client".to_owned());
static CLIENT_CACHE: LazyLock<moka::sync::Cache<String, Client>> = LazyLock::new(|| {
    moka::sync::Cache::builder()
        .max_capacity(1)
        .time_to_live(Duration::from_secs(CONFIG.sso_client_cache_expiration()))
        .build()
});

static REFRESH_CACHE: LazyLock<moka::future::Cache<String, Result<RefreshTokenResponse, String>>> =
    LazyLock::new(|| moka::future::Cache::builder().max_capacity(1000).time_to_live(Duration::from_secs(30)).build());

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct AllAdditionalClaims {
    #[serde(flatten)]
    pub claims: Value,
}

impl AdditionalClaims for AllAdditionalClaims {}

pub type MetadataClient = openidconnect::Client<
    AllAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<
        IdTokenFields<
            AllAdditionalClaims,
            EmptyExtraTokenFields,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >,
        CoreTokenType,
    >,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub type CustomClient = openidconnect::Client<
    AllAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<
        IdTokenFields<
            AllAdditionalClaims,
            EmptyExtraTokenFields,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >,
        CoreTokenType,
    >,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointSet,
>;

pub type RefreshTokenResponse = (Option<String>, AccessToken, Option<Duration>);

#[derive(Clone)]
pub struct Client {
    pub http_client: reqwest::Client,
    pub core_client: CustomClient,
}

impl Client {
    // Call the OpenId discovery endpoint to retrieve configuration
    async fn get_client() -> ApiResult<Self> {
        let client_id = ClientId::new(CONFIG.sso_client_id());
        let client_secret = ClientSecret::new(CONFIG.sso_client_secret());

        let issuer_url = CONFIG.sso_issuer_url()?;

        let http_client = match reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build() {
            Err(err) => err!(format!("Failed to build http client: {err}")),
            Ok(client) => client,
        };

        // Manually fetch the OpenID discovery doc so we can normalize the
        // `issuer` claim before strict validation. Some providers can advertise
        // the issuer with a trailing slash while the configured authority
        // representation strips it, causing a mismatch on discovery.
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.url().as_str().trim_end_matches('/')
        );
        let discovery_response = match http_client.get(&discovery_url).send().await {
            Err(err) => err!(format!("Failed to fetch OpenID discovery doc ({discovery_url}): {err}")),
            Ok(resp) => resp,
        };
        let discovery_text = match discovery_response.text().await {
            Err(err) => err!(format!("Failed to read OpenID discovery doc response body: {err}")),
            Ok(text) => text,
        };
        let mut discovery_json: Value = match serde_json::from_str(&discovery_text) {
            Err(err) => err!(format!("Failed to parse OpenID discovery doc as JSON: {err}")),
            Ok(json) => json,
        };
        if let Some(iss) = discovery_json.get("issuer").and_then(|v| v.as_str()) {
            let normalized = iss.trim_end_matches('/').to_owned();
            if normalized != iss {
                debug!("Normalized OpenID issuer claim by trimming trailing slash: {iss} -> {normalized}");
                discovery_json["issuer"] = Value::String(normalized);
            }
        }
        let provider_metadata: CoreProviderMetadata = match serde_json::from_value(discovery_json) {
            Err(err) => err!(format!("Failed to deserialize OpenID provider metadata: {err}")),
            Ok(metadata) => metadata,
        };

        // discover_async would normally fetch the JWKS automatically as part of
        // building the ProviderMetadata. Our manual discovery flow skipped that
        // step, so the metadata's JWKS field is empty and id_token signature
        // verification later fails with "Signature verification failed". Fetch
        // the JWKS now from the discovery jwks_uri and inject it.
        let jwks = match JsonWebKeySet::<CoreJsonWebKey>::fetch_async(provider_metadata.jwks_uri(), &http_client).await {
            Err(err) => err!(format!("Failed to fetch JWKS from {}: {err}", provider_metadata.jwks_uri().as_str())),
            Ok(jwks) => jwks,
        };
        let provider_metadata = provider_metadata.set_jwks(jwks);

        let base_client = MetadataClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret));

        let token_uri = if let Some(uri) = base_client.token_uri() {
            uri.clone()
        } else {
            err!("Failed to discover token_url, cannot proceed")
        };

        let user_info_url = if let Some(url) = base_client.user_info_url() {
            url.clone()
        } else {
            err!("Failed to discover user_info url, cannot proceed")
        };

        let core_client = base_client
            .set_redirect_uri(CONFIG.sso_redirect_url()?)
            .set_token_uri(token_uri)
            .set_user_info_url(user_info_url);

        Ok(Client {
            http_client,
            core_client,
        })
    }

    // Simple cache to prevent recalling the discovery endpoint each time
    pub async fn cached() -> ApiResult<Self> {
        if CONFIG.sso_client_cache_expiration() > 0 {
            match CLIENT_CACHE.get(&*CLIENT_CACHE_KEY) {
                Some(client) => Ok(client),
                None => Self::get_client().await.inspect(|client| {
                    debug!("Inserting new client in cache");
                    CLIENT_CACHE.insert(CLIENT_CACHE_KEY.clone(), client.clone());
                }),
            }
        } else {
            Self::get_client().await
        }
    }

    pub fn invalidate() {
        if CONFIG.sso_client_cache_expiration() > 0 {
            CLIENT_CACHE.invalidate(&*CLIENT_CACHE_KEY);
        }
    }

    // The `state` is encoded using base64 to ensure no issue with providers (It contains the Organization identifier).
    pub async fn authorize_url(
        state: OIDCState,
        client_challenge: OIDCCodeChallenge,
        redirect_uri: String,
    ) -> ApiResult<(Url, SsoAuth)> {
        let scopes = CONFIG.sso_scopes_vec().into_iter().map(Scope::new);
        let base64_state = data_encoding::BASE64.encode(state.to_string().as_bytes());

        let client = Self::cached().await?;
        let mut auth_req = client
            .core_client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                || CsrfToken::new(base64_state),
                Nonce::new_random,
            )
            .add_scopes(scopes)
            .add_extra_params(CONFIG.sso_authorize_extra_params_vec());

        if CONFIG.sso_pkce() {
            auth_req = auth_req
                .add_extra_param::<&str, String>("code_challenge", client_challenge.clone().into())
                .add_extra_param("code_challenge_method", "S256");
        }

        let (auth_url, _, nonce) = auth_req.url();
        Ok((auth_url, SsoAuth::new(state, client_challenge, nonce.secret().clone(), redirect_uri)))
    }

    pub async fn exchange_code(
        &self,
        code: OIDCCode,
        client_verifier: OIDCCodeVerifier,
        sso_auth: &SsoAuth,
    ) -> ApiResult<(
        StandardTokenResponse<
            IdTokenFields<
                AllAdditionalClaims,
                EmptyExtraTokenFields,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
            >,
            CoreTokenType,
        >,
        IdTokenClaims<AllAdditionalClaims, CoreGenderClaim>,
    )> {
        let oidc_code = AuthorizationCode::new(code.to_string());

        let mut exchange = self.core_client.exchange_code(oidc_code);

        let verifier = PkceCodeVerifier::new(client_verifier.into());
        if CONFIG.sso_pkce() {
            exchange = exchange.set_pkce_verifier(verifier);
        } else {
            let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
            if challenge.as_str() != String::from(sso_auth.client_challenge.clone()) {
                err!(format!("PKCE client challenge failed"))
            }
        }

        match exchange.request_async(&self.http_client).await {
            Err(err) => err!(format!("Failed to contact token endpoint: {:?}", err)),
            Ok(token_response) => {
                let oidc_nonce = Nonce::new(sso_auth.nonce.clone());

                let Some(id_token) = token_response.extra_fields().id_token() else {
                    err!("Token response did not contain an id_token")
                };

                if CONFIG.sso_debug_tokens() {
                    debug!("Id token: {}", id_token.to_string());
                    debug!("Access token: {}", token_response.access_token().secret());
                    debug!("Refresh token: {:?}", token_response.refresh_token().map(RefreshToken::secret));
                    debug!("Expiration time: {:?}", token_response.expires_in());
                }

                let id_claims = match id_token.claims(&self.vw_id_token_verifier(), &oidc_nonce) {
                    Ok(claims) => {
                        // Manual issuer match with trailing-slash normalization.
                        // claims.issuer() returns &IssuerUrl (inherent method, not Option).
                        let token_iss = claims.issuer().url().as_str();
                        let configured = CONFIG.sso_authority();
                        if token_iss.trim_end_matches('/') != configured.trim_end_matches('/') {
                            Self::invalidate();
                            err!(format!(
                                "id_token issuer ({token_iss}) does not match configured SSO_AUTHORITY ({configured})"
                            ));
                        }
                        claims.clone()
                    }
                    Err(err) => {
                        Self::invalidate();
                        err!(format!("Could not read id_token claims, {err}"));
                    }
                };

                Ok((token_response, id_claims))
            }
        }
    }

    pub async fn user_info(
        &self,
        access_token: AccessToken,
    ) -> ApiResult<UserInfoClaims<AllAdditionalClaims, CoreGenderClaim>> {
        match self.core_client.user_info(access_token, None).request_async(&self.http_client).await {
            Err(err) => err!(format!("Request to user_info endpoint failed: {err}")),
            Ok(user_info) => Ok(user_info),
        }
    }

    pub async fn check_validity(access_token: String) -> EmptyResult {
        let client = Client::cached().await?;
        match client.user_info(AccessToken::new(access_token)).await {
            Err(err) => {
                err_silent!(format!("Failed to retrieve user info, token has probably been invalidated: {err}"))
            }
            Ok(_) => Ok(()),
        }
    }

    pub fn vw_id_token_verifier(&self) -> CoreIdTokenVerifier<'_> {
        // Authentik 2026.x emits the `iss` claim in the id_token WITH a trailing
        // slash. Disable strict library issuer match; JWKS signature validation
        // still protects integrity. Manual normalized check is done by caller.
        let mut verifier = self.core_client.id_token_verifier()
            .require_issuer_match(false);
        if let Some(regex_str) = CONFIG.sso_audience_trusted() {
            match Regex::new(&regex_str) {
                Ok(regex) => {
                    verifier = verifier.set_other_audience_verifier_fn(move |aud| regex.is_match(aud));
                }
                Err(err) => {
                    error!("Failed to parse SSO_AUDIENCE_TRUSTED={regex_str} regex: {err}");
                }
            }
        }
        verifier
    }

    pub async fn exchange_refresh_token(&self, refresh_token: String) -> ApiResult<RefreshTokenResponse> {
        REFRESH_CACHE
            .get_with(refresh_token.clone(), async move { self.exchange_refresh_token_impl(refresh_token).await })
            .await
            .map_err(Into::into)
    }

    async fn exchange_refresh_token_impl(&self, refresh_token: String) -> Result<RefreshTokenResponse, String> {
        let rt = RefreshToken::new(refresh_token);

        match self.core_client.exchange_refresh_token(&rt).request_async(&self.http_client).await {
            Err(err) => {
                error!("Request to exchange_refresh_token endpoint failed: {err}");
                Err(format!("Request to exchange_refresh_token endpoint failed: {err}"))
            }
            Ok(token_response) => Ok((
                token_response.refresh_token().map(|token| token.secret().clone()),
                token_response.access_token().clone(),
                token_response.expires_in(),
            )),
        }
    }
}

trait AuthorizationRequestExt<'a> {
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(self, params: Vec<(N, V)>) -> Self;
}

impl<'a, AD: AuthDisplay, P: AuthPrompt, RT: ResponseType> AuthorizationRequestExt<'a>
    for AuthorizationRequest<'a, AD, P, RT>
{
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(mut self, params: Vec<(N, V)>) -> Self {
        for (key, value) in params {
            self = self.add_extra_param(key, value);
        }
        self
    }
}
