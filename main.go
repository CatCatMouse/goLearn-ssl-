package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	max_ := new(big.Int).Lsh(big.NewInt(1), 128)
	// 证书序列号: 具有唯一性
	serialNumber, _ := rand.Int(rand.Reader, max_)
	// 证书标题
	subject := pkix.Name{
		Organization:       []string{"Go Web Learning Co."},
		OrganizationalUnit: []string{"ssl test"},
		CommonName:         "Go Web Learning ssl Test",
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, // 用户服务器身份验证操作
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},               // 用户服务器身份验证操作
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},                           // 只能在IP地址 127.0.0.1上运行
	}
	// 生成rsa私钥
	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	// der编码
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk)
	// 将证书编码到cert.pem中
	certOut, _ := os.Create("Cert.pem")
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	// 把秘钥以pem编码的方式编码到key.pem中
	keyOut, _ := os.Create("Key.pem")
	_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})

	defer func() {
		_ = certOut.Close()
		_ = keyOut.Close()
	}()

}
