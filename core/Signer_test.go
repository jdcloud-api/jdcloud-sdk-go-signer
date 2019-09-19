package core

import (
	"net/http"
	"net/url"
	"testing"
)

func TestSigner(t *testing.T) {
	host := "test.cn-north-1.jdcloud-api.net"
	path := "/v1/region/cn-north-1/test"
	method := "POST"

	var header = make(http.Header)
	buildNonce(header) // 必须包含x-jdcloud-nonce
	buildTime(header)  // 必须包含x-jdcloud-date
	header.Set("content-type", "application/json")

	// query可以为nil
	var query = make(url.Values)
	query["filters.1.name"] = []string{"id"}
	query["filters.1.values.1"] = []string{"v1"}
	query["filters.1.values.2"] = []string{"v2"}

	// body可以为""
	body := ""

	Credential := NewCredential("access key", "secret key")
	Logger := NewDefaultLogger(LogInfo)
	signer := NewSigner(*Credential, Logger)

	sign, err := signer.Sign(host, path, method, header, query, body)
	trueSign := "JDCLOUD2-HMAC-SHA256 Credential=access key/20190214/cn-north-1/test/jdcloud2_request, SignedHeaders=content-type;host;x-jdcloud-date;x-jdcloud-nonce, Signature=ab7f411c1af4d3938f69a24539572418fa4dcdb40e3c0dd4aa329fbca091688e"
	if err != nil || trueSign != sign {
		println(sign)
		t.Error("validate signature failed", err)
	}
	header.Set(HeaderJdcloudAuthorization, sign)
}

func TestBackSigner(t *testing.T) {
	host := "test.cn-north-1.jdcloud-api.net"
	uri := "/v1/region/cn-north-1/test"
	method := "PATCH"
	var query = make(url.Values)
	query["filters.1.name"] = []string{"id"}
	query["filters.1.values.1"] = []string{"v1"}
	query["filters.1.values.2"] = []string{"v2"}
	body := "this is body"

	var header = make(http.Header)
	buildNonce(header)
	buildTime(header)
	header.Set("content-type", "application/json")
	header.Set("Authorization", "JDCLOUD2-HMAC-SHA256 Credential=access key/20190214/cn-north-1/test/jdcloud2_request, SignedHeaders=content-type;x-jdcloud-date;x-jdcloud-nonce, Signature=1912eba02012ce6eb482302bae29cfa8e721ad66c188c533f9070e69aad2c896")

	Credential := NewCredential("access key", "secret key")
	Logger := NewDefaultLogger(LogInfo)
	signer := NewSigner(*Credential, Logger)
	sign, err := signer.BackendSign(host, uri, method, header, query, body)
	if err != nil || header.Get(HeaderJdcloudAuthorization) != sign {
		println(sign)
		t.Error("validate signature failed", err)
	}
}

func buildTime(header http.Header) {
	//date := time.Unix(1551600000, 0)
	//formattedTime := date.UTC().Format(TimeFormat)
	header.Set(HeaderJdcloudDate, "20190214T104514Z")
}

func buildNonce(header http.Header) {
	//nonce, _ := uuid.NewV4()
	//header.Set(core.HeaderJdcloudNonce, nonce.String())
	header.Set(HeaderJdcloudNonce, "test nonce")
}
