package websvr

import (
	"crypto/tls"
	x "crypto/x509"
	"io/ioutil"
	"log"

	"github.com/whiskerman/gmsm/gmtls"
	"github.com/whiskerman/gmsm/x509"
)

const (
	/*
		rsaCertPath     = "./certs/rsa_sign.cer"
		rsaKeyPath      = "./certs/rsa_sign_key.pem"
		RSACaCertPath   = "./certs/RSA_CA.cer"
		RSAAuthCertPath = "./certs/rsa_auth_cert.cer"
		RSAAuthKeyPath  = "./certs/rsa_auth_key.pem"
		SM2CaCertPath   = "./certs/SM2_CA.cer"
		SM2AuthCertPath = "./certs/sm2_auth_cert.cer"
		SM2AuthKeyPath  = "./certs/sm2_auth_key.pem"
		sm2SignCertPath = "./certs/sm2_sign_cert.cer"
		sm2SignKeyPath  = "./certs/sm2_sign_key.pem"
		sm2EncCertPath  = "./certs/sm2_enc_cert.cer"
		sm2EncKeyPath   = "./certs/sm2_enc_key.pem"
	*/
	rsaCertPath     = "./certs1/rsasign.crt"
	rsaKeyPath      = "./certs1/rsasign.key"
	RSACaCertPath   = "./certs1/ca.crt"
	RSAAuthCertPath = "./certs1/server.crt"
	RSAAuthKeyPath  = "./certs1/server.key"
	SM2CaCertPath   = "/Users/sean/workspace/nginxcerts/cacert.pem"
	SM2AuthCertPath = "/Users/sean/workspace/nginxcerts/certs/01.pem"
	SM2AuthKeyPath  = "/Users/sean/workspace/nginxcerts/keys/signcert.key.pem"
	sm2SignCertPath = "/Users/sean/workspace/nginxcerts/certs/01.pem"
	sm2SignKeyPath  = "/Users/sean/workspace/nginxcerts/keys/signcert.key.pem"
	sm2EncCertPath  = "/Users/sean/workspace/nginxcerts/certs/02.pem"
	sm2EncKeyPath   = "/Users/sean/workspace/nginxcerts/keys/enccert.key.pem"
)

// RSA配置
func LoadRsaConfig() (*gmtls.Config, error) {
	cert, err := gmtls.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		log.Println("LoadRsaConfig err")
		return nil, err
	}
	return &gmtls.Config{Certificates: []gmtls.Certificate{cert}}, nil
}

// SM2配置
func LoadSM2Config() (*gmtls.Config, error) {
	sigCert, err := gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		log.Println("LoadSM2Config err")
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		GMSupport:    &gmtls.GMSupport{},
		Certificates: []gmtls.Certificate{sigCert, encCert},
	}, nil
}

// 切换GMSSL/TSL
func LoadAutoSwitchConfig() (*gmtls.Config, error) {
	rsaKeypair, err := gmtls.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		log.Println("rsaCertPath err")
		return nil, err
	}
	sigCert, err := gmtls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		log.Println("sm2SignCertPath err")
		return nil, err
	}
	encCert, err := gmtls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		log.Println("sm2EncCertPath err")
		return nil, err

	}
	return gmtls.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaKeypair)
}

// 要求客户端身份认证
func LoadAutoSwitchConfigClientAuth() (*gmtls.Config, error) {
	config, err := LoadAutoSwitchConfig()
	if err != nil {
		return nil, err
	}
	// 设置需要客户端证书请求，标识需要进行客户端的身份认证
	config.ClientAuth = gmtls.RequireAndVerifyClientCert
	return config, nil
}

// 获取 客户端服务端双向身份认证 配置
func BothAuthConfig() (*gmtls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := gmtls.LoadX509KeyPair(SM2AuthCertPath, SM2AuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &gmtls.Config{
		GMSupport:          &gmtls.GMSupport{},
		RootCAs:            certPool,
		Certificates:       []gmtls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func SingleSideAuthConfig() (*gmtls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &gmtls.Config{
		GMSupport: &gmtls.GMSupport{},
		RootCAs:   certPool,
	}, nil
}

// 获取 客户端服务端双向身份认证 配置
func RsaBothAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := tls.LoadX509KeyPair(RSAAuthCertPath, RSAAuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func RsaSingleSideAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tls.Config{
		MaxVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}, nil
}
