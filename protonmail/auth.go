package protonmail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/emersion/hydroxide/logger"
)

type authInfoReq struct {
	Username string
}

type AuthInfo struct {
	version         int
	modulus         string
	serverEphemeral string
	salt            string
	srpSession      string
}

type AuthInfoResp struct {
	resp
	AuthInfo
	Version         int
	Modulus         string
	ServerEphemeral string
	Salt            string
	SRPSession      string
}

func (resp *AuthInfoResp) authInfo() *AuthInfo {
	info := &resp.AuthInfo
	info.version = resp.Version
	info.modulus = resp.Modulus
	info.serverEphemeral = resp.ServerEphemeral
	info.salt = resp.Salt
	info.srpSession = resp.SRPSession
	return info
}

func (c *Client) AuthInfo(username string) (*AuthInfo, error) {
	reqData := &authInfoReq{
		Username: username,
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth/info", reqData)
	if err != nil {
		return nil, err
	}

	var respData AuthInfoResp
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	return respData.authInfo(), nil
}

type authReq struct {
	Username        string
	SRPSession      string
	ClientEphemeral string
	ClientProof     string
}

type PasswordMode int

const (
	PasswordSingle PasswordMode = 1
	PasswordTwo                 = 2
)

type Auth struct {
	ExpiresAt    time.Time
	Scope        string
	UID          string
	AccessToken  string
	RefreshToken string
	UserID       string
	EventID      string
	PasswordMode PasswordMode
	TwoFactor    struct {
		Enabled int
		U2F     interface{} // TODO
		TOTP    int
	} `json:"2FA"`
}

type authResp struct {
	resp
	Auth
	ExpiresIn   int
	TokenType   string
	ServerProof string
}

func (resp *authResp) auth() *Auth {
	auth := &resp.Auth
	auth.ExpiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	return auth
}

func (c *Client) Auth(username, password string, info *AuthInfo) (*Auth, error) {
	if info == nil {
		var err error
		if info, err = c.AuthInfo(username); err != nil {
			return nil, err
		}
	}

	proofs, err := srp([]byte(password), info)
	if err != nil {
		return nil, fmt.Errorf("SRP failed during auth: %v", err)
	}

	reqData := &authReq{
		Username:        username,
		SRPSession:      info.srpSession,
		ClientEphemeral: base64.StdEncoding.EncodeToString(proofs.clientEphemeral),
		ClientProof:     base64.StdEncoding.EncodeToString(proofs.clientProof),
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth", reqData)
	if err != nil {
		return nil, err
	}

	var respData authResp
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	if err := proofs.VerifyServerProof(respData.ServerProof); err != nil {
		return nil, err
	}

	auth := respData.auth()
	c.uid = auth.UID
	c.accessToken = auth.AccessToken
	return auth, nil
}

func (c *Client) AuthTOTP(code string) (scope string, err error) {
	reqData := struct {
		TwoFactorCode string
	}{
		TwoFactorCode: code,
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth/2fa", reqData)
	if err != nil {
		return "", err
	}

	respData := struct {
		resp
		Scope string
	}{}
	if err := c.doJSON(req, &respData); err != nil {
		return "", err
	}

	return respData.Scope, nil
}

type authRefreshReq struct {
	RefreshToken string

	// Unused but required
	ResponseType string
	GrantType    string
	RedirectURI  string
}

func (c *Client) AuthRefresh(expiredAuth *Auth) (*Auth, error) {
	reqData := &authRefreshReq{
		RefreshToken: expiredAuth.RefreshToken,
		ResponseType: "token",
		GrantType:    "refresh_token",
		RedirectURI:  "http://www.protonmail.ch",
	}

	req, err := c.newJSONRequest(http.MethodPost, "/auth/refresh", reqData)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Pm-Uid", expiredAuth.UID)

	var respData authResp
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	auth := respData.auth()
	//auth.EventID = expiredAuth.EventID
	auth.PasswordMode = expiredAuth.PasswordMode
	return auth, nil
}

func (c *Client) ListKeySalts() (map[string][]byte, error) {
	req, err := c.newRequest(http.MethodGet, "/keys/salts", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		resp
		KeySalts []struct {
			ID      string
			KeySalt string
		}
	}
	if err := c.doJSON(req, &respData); err != nil {
		return nil, err
	}

	salts := make(map[string][]byte, len(respData.KeySalts))
	for _, salt := range respData.KeySalts {
		if salt.KeySalt == "" {
			salts[salt.ID] = nil
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(salt.KeySalt)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key salt payload: %v", err)
		}
		salts[salt.ID] = payload
	}

	return salts, nil
}

func unlockEntity(e *openpgp.Entity, passphraseBytes []byte) error {
	var privateKeys []*packet.PrivateKey

	// e.PrivateKey is a signing key
	if e.PrivateKey != nil {
		privateKeys = append(privateKeys, e.PrivateKey)
	}

	// e.Subkeys are encryption keys
	for _, subkey := range e.Subkeys {
		if subkey.PrivateKey != nil {
			privateKeys = append(privateKeys, subkey.PrivateKey)
		}
	}

	for _, priv := range privateKeys {
		if err := priv.Decrypt(passphraseBytes); err != nil {
			return err
		}
	}

	return nil
}

func decryptPrivateKeyToken(key *PrivateKey, userKeyRing openpgp.EntityList) ([]byte, error) {
	block, err := armor.Decode(strings.NewReader(key.Token))
	if err != nil {
		return nil, err
	}

	md, err := openpgp.ReadMessage(block.Body, userKeyRing, nil, nil)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	// TODO: check signer?
	_, err = openpgp.CheckArmoredDetachedSignature(userKeyRing, bytes.NewReader(b), strings.NewReader(key.Signature), nil)
	return b, err
}

func unlockPrivateKey(key *PrivateKey, userKeyRing openpgp.EntityList, keySalt []byte, passphraseBytes []byte) (*openpgp.Entity, error) {
	entity, err := key.Entity()
	if err != nil {
		return nil, err
	}

	if key.Token != "" {
		passphraseBytes, err = decryptPrivateKeyToken(key, userKeyRing)
	} else if keySalt != nil {
		passphraseBytes, err = computeKeyPassword(passphraseBytes, keySalt)
	}
	if err != nil {
		return nil, err
	}

	if err := unlockEntity(entity, passphraseBytes); err != nil {
		return nil, err
	}

	return entity, nil
}

func unlockKeyRing(keys []*PrivateKey, userKeyRing openpgp.EntityList, keySalts map[string][]byte, passphraseBytes []byte) (openpgp.EntityList, uint64, error) {
	var keyRing openpgp.EntityList
	var primaryKeyID uint64
	logger.Debug("unlockKeyRing called with %d keys", len(keys))
	
	for _, key := range keys {
		logger.Debug("processing key ID=%s, Fingerprint=%s, Active=%d, Primary=%d", 
			key.ID, key.Fingerprint, key.Active, key.Primary)
		
		if key.Active != 1 {
			logger.Debug("skipping inactive key %s", key.Fingerprint)
			continue
		}

		entity, err := unlockPrivateKey(key, userKeyRing, keySalts[key.ID], passphraseBytes)
		if err != nil {
			log.Printf("warning: failed to unlock key %v: %v", key.Fingerprint, err)
			continue
		}

		// Log the key algorithm type
		logger.Debug("successfully unlocked key %s, algorithm=%s (code=%d)", 
			key.Fingerprint, entity.PrimaryKey.PubKeyAlgo, entity.PrimaryKey.PubKeyAlgo)

		// Track the primary key
		if key.Primary == 1 {
			primaryKeyID = entity.PrimaryKey.KeyId
			logger.Debug("identified primary key: ID=%s, KeyId=%X", key.ID, primaryKeyID)
		}

		keyRing = append(keyRing, entity)
	}

	if len(keyRing) == 0 {
		return nil, 0, fmt.Errorf("failed to unlock any key")
	}
	logger.Debug("unlockKeyRing returning %d keys, primaryKeyID=%X", len(keyRing), primaryKeyID)
	return keyRing, primaryKeyID, nil
}

func (c *Client) Unlock(auth *Auth, keySalts map[string][]byte, passphrase string) (openpgp.EntityList, uint64, error) {
	c.uid = auth.UID
	c.accessToken = auth.AccessToken

	u, err := c.GetCurrentUser()
	if err != nil {
		return nil, 0, err
	}

	logger.Debug("unlocking %d user keys", len(u.Keys))
	userKeyRing, primaryKeyID, err := unlockKeyRing(u.Keys, nil, keySalts, []byte(passphrase))
	if err != nil {
		return nil, 0, err
	}
	logger.Debug("unlocked %d user keys successfully, primary key ID: %X", len(userKeyRing), primaryKeyID)

	// Log key types in user keyring
	for i, entity := range userKeyRing {
		logger.Debug("user key %d: algorithm=%s, keyid=%X", 
			i, entity.PrimaryKey.PubKeyAlgo, entity.PrimaryKey.KeyId)
	}

	addrs, err := c.ListAddresses()
	if err != nil {
		return nil, 0, err
	}

	// Start with user keys, not empty list
	var keyRing openpgp.EntityList
	keyRing = append(keyRing, userKeyRing...)
	logger.Debug("starting with %d user keys in keyring", len(userKeyRing))

	for _, addr := range addrs {
		logger.Debug("unlocking keys for address <%v> (%d keys)", addr.Email, len(addr.Keys))
		addrKeyRing, _, err := unlockKeyRing(addr.Keys, userKeyRing, keySalts, []byte(passphrase))
		if err != nil {
			log.Printf("warning: failed to unlock address <%v>: %v", addr.Email, err)
			continue
		}
		logger.Debug("unlocked %d keys for address <%v>", len(addrKeyRing), addr.Email)
		
		// Log key types in address keyring
		for i, entity := range addrKeyRing {
			logger.Debug("address %s key %d: algorithm=%s, keyid=%X", 
				addr.Email, i, entity.PrimaryKey.PubKeyAlgo, entity.PrimaryKey.KeyId)
		}

		keyRing = append(keyRing, addrKeyRing...)
	}

	if len(keyRing) == 0 {
		return nil, 0, fmt.Errorf("failed to unlock any key")
	}

	logger.Debug("total keys in final keyring: %d", len(keyRing))
	c.keyRing = keyRing

	return keyRing, primaryKeyID, nil
}

func (c *Client) Logout() error {
	req, err := c.newRequest(http.MethodDelete, "/auth", nil)
	if err != nil {
		return err
	}

	if err := c.doJSON(req, nil); err != nil {
		return err
	}

	c.uid = ""
	c.accessToken = ""
	c.keyRing = nil
	return nil
}
