package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ResponseError struct {
	StatusCode int
	Content    []byte
}

func (err *ResponseError) Error() string {
	return string(err.Content)
}

type Auth struct {
	firebaseAPIKey string
}

func NewAuth(firebaseAPIKey string) *Auth {
	return &Auth{
		firebaseAPIKey: firebaseAPIKey,
	}
}

func (auth *Auth) post(url string, request, response interface{}) error {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return err
	}
	res, err := http.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return &ResponseError{
				StatusCode: res.StatusCode,
				Content:    []byte(err.Error()),
			}
		}
		return &ResponseError{
			StatusCode: res.StatusCode,
			Content:    b,
		}
	}
	decoder := json.NewDecoder(res.Body)
	err = decoder.Decode(response)
	if err != nil {
		return err
	}
	return nil
}

type ExchangeCustomTokenForAnIDAndRefreshTokenRequest struct {
	Token             string `json:"token"`
	ReturnSecureToken bool   `json:"bool"`
}

type ExchangeCustomTokenForAnIDAndRefreshTokenResponse struct {
	IDToken      string `json:"idToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
}

func (auth *Auth) ExchangeCustomTokenForAnIDAndRefreshToken(req *ExchangeCustomTokenForAnIDAndRefreshTokenRequest) (*ExchangeCustomTokenForAnIDAndRefreshTokenResponse, error) {
	var res ExchangeCustomTokenForAnIDAndRefreshTokenResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type ExchangeARefreshTokenForAnIDTokenRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
}

type ExchangeARefreshTokenForAnIDTokenResponse struct {
	ExpiresIn    string `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	UserID       string `json:"user_id"`
	ProjectID    string `json:"project_id"`
}

func (auth *Auth) ExchangeARefreshTokenForAnIDToken(req *ExchangeARefreshTokenForAnIDTokenRequest) (*ExchangeARefreshTokenForAnIDTokenResponse, error) {
	var res ExchangeARefreshTokenForAnIDTokenResponse
	err := auth.post(fmt.Sprintf("https://securetoken.googleapis.com/v1/token?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type SignUpWithEmailPasswordRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type SignUpWithEmailPasswordResponse struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
}

func (auth *Auth) SignUpWithEmailPassword(req *SignUpWithEmailPasswordRequest) (*SignUpWithEmailPasswordResponse, error) {
	var res SignUpWithEmailPasswordResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type SignInWithEmailPasswordRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type SignInWithEmailPasswordResponse struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
	Registered   bool   `json:"registered"`
}

func (auth *Auth) SignInWithEmailPassword(req *SignInWithEmailPasswordRequest) (*SignInWithEmailPasswordResponse, error) {
	var res SignInWithEmailPasswordResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type SignInAnonymouslyRequest struct {
	ReturnSecureToken bool `json:"returnSecureToken"`
}

type SignInAnonymouslyResponse struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
}

func (auth *Auth) SignInAnonymously(req *SignInAnonymouslyRequest) (*SignInAnonymouslyResponse, error) {
	var res SignInAnonymouslyResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type SignInWithOAuthCredentialRequest struct {
	RequestURI          string `json:"requestUri"`
	PostBody            string `json:"postBody"`
	ReturnSecureToken   bool   `json:"returnSecureToken"`
	ReturnIDPCredential bool   `json:"returnIdpCredential"`
}

type SignInWithOAuthCredentialResponse struct {
	FederatedID      string `json:"federatedId"`
	ProviderID       string `json:"providerId"`
	LocalID          string `json:"localId"`
	EmailVerified    bool   `json:"emailVerified"`
	Email            string `json:"email"`
	OAuthIDToken     string `json:"oauthIdToken"`
	OAuthAccessToken string `json:"oauthAccessToken"`
	RawUserInfo      string `json:"rawUserInfo"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	FullName         string `json:"fullName"`
	DisplayName      string `json:"displayName"`
	PhotoURL         string `json:"photoUrl"`
	IDToken          string `json:"idToken"`
	RefreshToken     string `json:"refreshToken"`
	ExpiresIn        string `json:"expiresIn"`
	NeedConfirmation bool   `json:"needConfirmation"`
}

func (auth *Auth) SignInWithOAuthCredential(req *SignInWithOAuthCredentialRequest) (*SignInWithOAuthCredentialResponse, error) {
	var res SignInWithOAuthCredentialResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type FetchProvidersForEmailRequest struct {
	Identifier  string `json:"identifier"`
	ContinueURI string `json:"continueUri"`
}

type FetchProvidersForEmailResponse struct {
	AllProviders []string `json:"allProviders"`
	Registered   bool     `json:"registered"`
}

func (auth *Auth) FetchProvidersForEmail(req *FetchProvidersForEmailRequest) (*FetchProvidersForEmailResponse, error) {
	var res FetchProvidersForEmailResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type SendPasswordResetEmailRequest struct {
	RequestType string `json:"requestType"`
	Email       string `json:"email"`
}

type SendPasswordResetEmailResponse struct {
	Email string `json:"email"`
}

func (auth *Auth) SendPasswordResetEmail(req *SendPasswordResetEmailRequest) (*SendPasswordResetEmailResponse, error) {
	var res SendPasswordResetEmailResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type VerifyPasswordResetCodeRequest struct {
	OOBCode string `json:"oobCode"`
}

type VerifyPasswordResetCodeResponse struct {
	Email       string `json:"email"`
	RequestType string `json:"requestType"`
}

func (auth *Auth) VerifyPasswordResetCode(req *VerifyPasswordResetCodeRequest) (*VerifyPasswordResetCodeResponse, error) {
	var res VerifyPasswordResetCodeResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type ConfirmPasswordResetRequest struct {
	OOBCode     string `json:"oobCode"`
	NewPassword string `json:"newPassword"`
}

type ConfirmPasswordResetResponse struct {
	Email       string `json:"email"`
	RequestType string `json:"requestType"`
}

func (auth *Auth) ConfirmPasswordReset(req *ConfirmPasswordResetRequest) (*ConfirmPasswordResetResponse, error) {
	var res ConfirmPasswordResetResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type ChangeEmailRequest struct {
	IDToken           string `json:"idToken"`
	Email             string `json:"email"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type ChangeEmailResponse struct {
	LocalID          string                   `json:"localId"`
	Email            string                   `json:"email"`
	PasswordHash     string                   `json:"passwordHash"`
	ProviderUserInfo []map[string]interface{} `json:"providerUserInfo"`
	IDToken          string                   `json:"idToken"`
	RefreshToken     string                   `json:"refreshToken"`
	ExpiresIn        string                   `json:"expiresIn"`
}

func (auth *Auth) ChangeEmail(req *ChangeEmailRequest) (*ChangeEmailResponse, error) {
	var res ChangeEmailResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:update?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type ChangePasswordRequest struct {
	IDToken           string `json:"idToken"`
	Password          string `json:"password"`
	ReturnSecureToken string `json:"returnSecureToken"`
}

type ChangePasswordResponse struct {
	LocalID          string                   `json:"localId"`
	Email            string                   `json:"email"`
	PasswordHash     string                   `json:"passwordHash"`
	ProviderUserInfo []map[string]interface{} `json:"providerUserInfo"`
	IDToken          string                   `json:"idToken"`
	RefreshToken     string                   `json:"refreshToken"`
	ExpiresIn        string                   `json:"expiresIn"`
}

func (auth *Auth) ChangePassword(req *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	var res ChangePasswordResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:update?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type UpdateProfileRequest struct {
	IDToken           string   `json:"idToken"`
	DisplayName       string   `json:"displayName"`
	PhotoURL          string   `json:"photoUrl"`
	DeleteAttribute   []string `json:"deleteAttribute"`
	ReturnSecureToken bool     `json:"returnSecureToken"`
}

type UpdateProfileResponse struct {
	LocalID          string                   `json:"localId"`
	Email            string                   `json:"email"`
	DisplayName      string                   `json:"displayName"`
	PhotoURL         string                   `json:"photoUrl"`
	PasswordHash     string                   `json:"passwordHash"`
	ProviderUserInfo []map[string]interface{} `json:"providerUserInfo"`
	IDToken          string                   `json:"idToken"`
	RefreshToken     string                   `json:"refreshToken"`
	ExpiresIn        string                   `json:"expiresIn"`
}

func (auth *Auth) UpdateProfile(req *UpdateProfileRequest) (*UpdateProfileResponse, error) {
	var res UpdateProfileResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:update?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type GetUserDataRequest struct {
	IDToken string `json:"idToken"`
}

type GetUserDataResponseElement struct {
	LocalID           string                   `json:"localId"`
	Email             string                   `json:"email"`
	EmailVerified     bool                     `json:"emailVerified"`
	DisplayName       string                   `json:"displayName"`
	ProviderUserInfo  []map[string]interface{} `json:"providerUserInfo"`
	PhotoURL          string                   `json:"photoUrl"`
	PasswordHash      string                   `json:"passwordHash"`
	PasswordUpdatedAt float32                  `json:"passwordUpdatedAt"`
	ValidSince        string                   `json:"validSince"`
	Disabled          bool                     `json:"disabled"`
	LastLoginAt       string                   `json:"lastLoginAt"`
	CreatedAt         string                   `json:"createdAt"`
	CustomAuth        bool                     `json:"customAuth"`
}

type GetUserDataResponse struct {
	Users []GetUserDataResponseElement `json:"users"`
}

func (auth *Auth) GetUserData(req *GetUserDataRequest) (*GetUserDataResponse, error) {
	var res GetUserDataResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type LinkWithEmailPasswordRequest struct {
	IDToken           string `json:"idToken"`
	Email             string `json:"email"`
	Password          string `json:"password"`
	ReturnSecureToken bool   `json:"returnSecureToken"`
}

type LinkWithEmailPasswordResponse struct {
	LocalID          string                   `json:"localId"`
	Email            string                   `json:"email"`
	DisplayName      string                   `json:"displayName"`
	PhotoURL         string                   `json:"photoUrl"`
	PasswordHash     string                   `json:"passwordHash"`
	ProviderUserInfo []map[string]interface{} `json:"providerUserInfo"`
	EmailVerified    bool                     `json:"emailVerified"`
	IDToken          string                   `json:"idToken"`
	RefreshToken     string                   `json:"refreshToken"`
	ExpiresIn        string                   `json:"expiresIn"`
}

func (auth *Auth) LinkWithEmailPassword(req *LinkWithEmailPasswordRequest) (*LinkWithEmailPasswordResponse, error) {
	var res LinkWithEmailPasswordResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:update?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type LinkWithOAuthCredentialRequest struct {
	IDToken             string `json:"idToken"`
	RequestURI          string `json:"requestUri"`
	PostBody            string `json:"postBody"`
	ReturnSecureToken   bool   `json:"returnSecureToken"`
	ReturnIDPCredential bool   `json:"returnIDPCredential"`
}

type LinkWithOAuthCredentialResponse struct {
	FederatedID      string `json:"federatedId"`
	ProviderID       string `json:"providerId"`
	LocalID          string `json:"localId"`
	EmailVerified    bool   `json:"emailVerified"`
	Email            string `json:"email"`
	OAuthIDToken     string `json:"oauthIdToken"`
	OAuthAccessToken string `json:"oauthAccessToken"`
	OAuthTokenSecret string `json:"oauthTokenSecret"`
	RawUserInfo      string `json:"rawUserInfo"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	FullName         string `json:"fullName"`
	DisplayName      string `json:"displayName"`
	PhotoURL         string `json:"photoUrl"`
	IDToken          string `json:"idToken"`
	RefreshToken     string `json:"refreshToken"`
	ExpiresIn        string `json:"expiresIn"`
	NeedConfirmation bool   `json:"needConfirmation"`
}

func (auth *Auth) LinkWithOAuthCredential(req *LinkWithOAuthCredentialRequest) (*LinkWithOAuthCredentialResponse, error) {
	var res LinkWithOAuthCredentialResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type UnlinkProviderRequest struct {
	IDToken        string   `json:"idToken"`
	DeleteProvider []string `json:"deleteProvider"`
}

type UnlinkProviderResponse struct {
	LocalID          string                   `json:"localId"`
	Email            string                   `json:"email"`
	DisplayName      string                   `json:"displayName"`
	PhotoURL         string                   `json:"photoUrl"`
	PasswordHash     string                   `json:"passwordHash"`
	ProviderUserInfo []map[string]interface{} `json:"providerUserInfo"`
	EmailVerified    bool                     `json:"emailVerified"`
}

func (auth *Auth) UnlinkProvider(req *UnlinkProviderRequest) (*UnlinkProviderResponse, error) {
	var res UnlinkProviderResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:update?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type SendEmailVerificationRequest struct {
	RequestType string `json:"requestType"`
	IDToken     string `json:"idToken"`
}

type SendEmailVerificationResponse struct {
	Email string `json:"email"`
}

func (auth *Auth) SendEmailVerification(req *SendEmailVerificationRequest) (*SendEmailVerificationResponse, error) {
	var res SendEmailVerificationResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type ConfirmEmailVerificationRequest struct {
	OOBCode string `json:"oobCode"`
}

type ConfirmEmailVerificationResponse struct {
	Email            string                   `json:"email"`
	DisplayName      string                   `json:"displayName"`
	PhotoURL         string                   `json:"photoUrl"`
	PasswordHash     string                   `json:"passwordHash"`
	ProviderUserInfo []map[string]interface{} `json:"providerUserInfo"`
	EmailVerified    bool                     `json:"emailVerified"`
}

func (auth *Auth) ConfirmEmailVerification(req *ConfirmEmailVerificationRequest) (*ConfirmEmailVerificationResponse, error) {
	var res ConfirmEmailVerificationResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:update?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

type DeleteAccountRequest struct {
	IDToken string `json:"idToken"`
}

type DeleteAccountResponse struct{}

func (auth *Auth) DeleteAccount(req *DeleteAccountRequest) (*DeleteAccountResponse, error) {
	var res DeleteAccountResponse
	err := auth.post(fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:delete?key=%s", auth.firebaseAPIKey), req, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
