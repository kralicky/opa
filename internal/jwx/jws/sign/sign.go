package sign

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
)

// GetSigningKey returns a *rsa.PrivateKey or *ecdsa.PrivateKey typically encoded in PEM blocks of type "RSA PRIVATE KEY"
// or "EC PRIVATE KEY" for RSA and ECDSA family of algorithms.
// For HMAC family, it return a []byte value
func GetSigningKey(key string, alg jwa.SignatureAlgorithm) (interface{}, error) {
	switch alg {
	case jwa.RS256, jwa.RS384, jwa.RS512, jwa.PS256, jwa.PS384, jwa.PS512:
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block containing the key")
		}

		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			pkcs8priv, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("error parsing private key (%v), (%v)", err, err2)
			}
			return pkcs8priv, nil
		}
		return priv, nil
	case jwa.ES256, jwa.ES384, jwa.ES512:
		block, _ := pem.Decode([]byte(key))
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block containing the key")
		}

		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			pkcs8priv, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("error parsing private key (%v), (%v)", err, err2)
			}
			return pkcs8priv, nil
		}
		return priv, nil
	case jwa.HS256, jwa.HS384, jwa.HS512:
		return []byte(key), nil
	case jwa.EdDSA:
		return ed25519.PrivateKey(key), nil
	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", alg)
	}
}
