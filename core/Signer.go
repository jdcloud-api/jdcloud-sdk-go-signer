// Copyright 2018-2025 JDCLOUD.COM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This signer is modified from AWS V4 signer algorithm.

package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gofrs/uuid"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	authHeaderPrefix           = "JDCLOUD2-HMAC-SHA256"
	TimeFormat                 = "20060102T150405Z"
	shortTimeFormat            = "20060102"
	headerJdcloudContentSha256 = "x-jdcloud-content-sha256"
	// emptyStringSHA256 is a SHA256 of an empty string
	emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
)

var ignoredHeaders = []string{HeaderJdcloudAuthorization, "User-Agent", "X-Jdcloud-Request-Id"}
var noEscape [256]bool

func init() {
	for i := 0; i < len(noEscape); i++ {
		// expects every character except these to be escaped
		noEscape[i] = (i >= 'A' && i <= 'Z') ||
			(i >= 'a' && i <= 'z') ||
			(i >= '0' && i <= '9') ||
			i == '-' ||
			i == '.' ||
			i == '_' ||
			i == '~'
	}
}

type Signer struct {
	Credentials Credential
	Logger      Logger
}

func NewSigner(credsProvider Credential, logger Logger) *Signer {
	return &Signer{
		Credentials: credsProvider,
		Logger:      logger,
	}
}

type signingCtx struct {
	ServiceName string
	Region      string
	Host        string
	Path        string
	Method      string
	RawQuery    string

	Header           http.Header
	Body             string
	Query            url.Values
	Time             time.Time
	ExpireTime       time.Duration
	SignedHeaderVals http.Header

	credValues         Credential
	formattedTime      string
	formattedShortTime string

	bodyDigest       string
	signedHeaders    string
	canonicalHeaders string
	canonicalString  string
	credentialString string
	stringToSign     string
	signature        string
	authorization    string
	signedHeaderKeys []string
}

// Sign signs the request by using AWS V4 signer algorithm, and adds Authorization header
func (v4 Signer) Sign(host string, path string, method string, header http.Header, query url.Values, body string) (string, error) {
	err := v4.checkParameters(host, path, method, header)
	if err != nil {
		return "", err
	}
	signTime, err := time.Parse(TimeFormat, header.Get(HeaderJdcloudDate))
	if err != nil {
		return "", err
	}
	if v4.isRequestSigned(header) {
		signTime = time.Now()
	}
	return v4.signWithBody(host, path, strings.ToUpper(method), header, query, body, "test", "cn-north-1", 0, signTime, nil)
}

// secretKey, host, path, method, headers, queryString, body
func (v4 Signer) BackendSign(host string, path string, method string, header http.Header, query url.Values, body string) (string, error) {
	v4.Logger.Log(LogInfo, host, path, method)
	v4.Logger.Log(LogInfo, header)
	v4.Logger.Log(LogInfo, query)
	v4.Logger.Log(LogInfo, body)
	err := v4.checkParameters(host, path, method, header)
	if err != nil {
		return "", err
	}
	signTime, err := time.Parse(TimeFormat, header.Get(HeaderJdcloudDate))
	if err != nil {
		return "", err
	}
	authorization := header.Get(HeaderJdcloudAuthorization)
	if authorization == "" {
		return "", errors.New("header:authorization is empty")
	}
	return v4.signForBackend(host, EscapePath(path, false), method, header, query, body, authorization, 0, signTime)
}

func (v4 Signer) checkParameters(host string, path string, method string, header http.Header) error {
	var msg string
	if host == "" {
		msg = "host is empty"
	}
	if path == "" {
		msg = "path is empty"
	}
	if method == "" {
		msg = "method is empty"
	}
	if header == nil {
		msg = "header is empty"
	}
	if header.Get(HeaderJdcloudNonce) == "" {
		msg = "can not get x-jdcloud-nonce in HEAD"
	}
	if header.Get(HeaderJdcloudDate) == "" {
		msg = "can not get x-jdcloud-date in HEAD"
	}
	if msg == "" {
		return nil
	}
	return errors.New(msg)
}

func (v4 Signer) signWithBody(host string, path string, method string, header http.Header, query url.Values, body string, service string, region string, exp time.Duration,
	signTime time.Time, signedHeaderKeys []string) (string, error) {

	ctx := &signingCtx{
		Host:             host,
		Path:             path,
		Method:           method,
		Header:           header,
		Query:            query,
		Body:             body,
		Time:             signTime,
		ExpireTime:       exp,
		ServiceName:      service,
		Region:           region,
		signedHeaderKeys: signedHeaderKeys,
	}

	ctx.credValues = v4.Credentials
	ctx.build()

	v4.logSigningInfo(ctx)
	return ctx.authorization, nil
}

func (v4 Signer) signForBackend(host string, path string, method string, header http.Header, query url.Values, body string, authorization string, exp time.Duration,
	signTime time.Time) (string, error) {
	//algorithm := authorization[0 : strings.Index(authorization, "Credential=")-1] // JDCLOUD2-HMAC-SHA256
	signedHeaders := strings.Replace(authorization[strings.Index(authorization, "SignedHeaders="):(strings.Index(authorization, "Signature=")-2)], "SignedHeaders=", "", 1)
	signedHeaderKeys := strings.Split(signedHeaders, ";") // content-type;x-jdcloud-date;x-jdcloud-nonce

	credential := strings.Replace(authorization[strings.Index(authorization, "Credential="):(strings.Index(authorization, "SignedHeaders=")-2)], "Credential=", "", 1)
	credentialArray := strings.Split(credential, "/")
	//assessKey := credentialArray[0],date := credentialArray[1],credentialScope := credential[strings.Index(credential, "/")+1 : len(credential)]
	region := credentialArray[2]
	service := credentialArray[3]
	return v4.signWithBody(host, path, strings.ToUpper(method), header, query, body, service, region, 0, signTime, signedHeaderKeys)
}

const logSignInfoMsg = `DEBUG: Request Signature:
---[ CANONICAL STRING  ]-----------------------------
%s
---[ STRING TO SIGN ]--------------------------------
%s%s
-----------------------------------------------------`

func (v4 *Signer) logSigningInfo(ctx *signingCtx) {
	signedURLMsg := ""
	msg := fmt.Sprintf(logSignInfoMsg, ctx.canonicalString, ctx.stringToSign, signedURLMsg)
	v4.Logger.Log(LogInfo, msg)
}

// isRequestSigned returns if the request is currently signed or presigned
func (v4 *Signer) isRequestSigned(header http.Header) bool {
	if header.Get(HeaderJdcloudAuthorization) != "" {
		return true
	}
	return false
}

func (ctx *signingCtx) build() {
	ctx.buildHost()
	ctx.buildPath()
	ctx.buildTime()
	ctx.buildRawQuery()
	ctx.buildCredentialString() // no depends
	ctx.buildBodyDigest()
	if ctx.signedHeaderKeys == nil {
		ctx.buildCanonicalHeaders()
	} else {
		ctx.buildCanonicalHeadersForBackend()
	}

	ctx.buildCanonicalString() // depends on canon headers / signed headers
	ctx.buildStringToSign()    // depends on canon string
	ctx.buildSignature()       // depends on string to sign

	parts := []string{
		authHeaderPrefix + " Credential=" + ctx.credValues.AccessKey + "/" + ctx.credentialString,
		"SignedHeaders=" + ctx.signedHeaders,
		"Signature=" + ctx.signature,
	}
	ctx.authorization = strings.Join(parts, ", ")
}

func (ctx *signingCtx) buildHost() {
	ctx.Host = strings.Replace(strings.ToLower(ctx.Host), "https://", "", 1)
	ctx.Host = strings.Replace(ctx.Host, "http://", "", 1)
}

func (ctx *signingCtx) buildPath() {
	if strings.Index(ctx.Path, "?") >= 0 {
		ctx.Path = ctx.Path[0:strings.Index(ctx.Path, "?")]
	}
	if ctx.Path != "" && ctx.Path[len(ctx.Path)-1:len(ctx.Path)] == "/" {
		ctx.Path = ctx.Path[0 : len(ctx.Path)-1]
	}
	if ctx.Path == "" {
		ctx.Path = "/"
	}
}

func (ctx *signingCtx) buildTime() {
	ctx.formattedTime = ctx.Time.UTC().Format(TimeFormat)
	ctx.formattedShortTime = ctx.Time.UTC().Format(shortTimeFormat)
	//ctx.Header.Set(HeaderJdcloudDate, ctx.formattedTime)
}

func (ctx *signingCtx) buildRawQuery() {
	if ctx.Query != nil {
		keysSort := make([]string, 0)
		for key := range ctx.Query {
			sort.Strings(ctx.Query[key])
			keysSort = append(keysSort, key)
		}
		sort.Strings(keysSort)
		for i := range keysSort {
			if ctx.RawQuery != "" {
				ctx.RawQuery = strings.Join([]string{ctx.RawQuery, "&", keysSort[i], "=", strings.Join(ctx.Query[keysSort[i]], "")}, "")
			} else {
				ctx.RawQuery = strings.Join([]string{keysSort[i], "=", strings.Join(ctx.Query[keysSort[i]], "")}, "")
			}
		}
	}
}

func (ctx *signingCtx) buildNonce() {
	nonce, _ := uuid.NewV4()
	ctx.Header.Set(HeaderJdcloudNonce, nonce.String())
}

func (ctx *signingCtx) buildCredentialString() {
	ctx.credentialString = strings.Join([]string{
		ctx.formattedShortTime,
		ctx.Region,
		ctx.ServiceName,
		"jdcloud2_request",
	}, "/")
}

func (ctx *signingCtx) buildCanonicalHeaders() {
	unsignedHeaders := ctx.Header
	var headers []string
	headers = append(headers, "host")
	for k, v := range unsignedHeaders {
		canonicalKey := http.CanonicalHeaderKey(k)
		if shouldIgnore(canonicalKey, ignoredHeaders) {
			continue // ignored header
		}
		if ctx.SignedHeaderVals == nil {
			ctx.SignedHeaderVals = make(http.Header)
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := ctx.SignedHeaderVals[lowerCaseKey]; ok {
			// include additional values
			ctx.SignedHeaderVals[lowerCaseKey] = append(ctx.SignedHeaderVals[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		ctx.SignedHeaderVals[lowerCaseKey] = v
	}
	sort.Strings(headers)

	ctx.signedHeaders = strings.Join(headers, ";")

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		if k == "host" {
			headerValues[i] = "host:" + ctx.Host
		} else {
			headerValues[i] = k + ":" +
				strings.Join(ctx.SignedHeaderVals[k], ",")
		}
	}
	stripExcessSpaces(headerValues)
	ctx.canonicalHeaders = strings.Join(headerValues, "\n")
}

func (ctx *signingCtx) buildCanonicalHeadersForBackend() {
	ctx.Header.Set("host", ctx.Host)
	var unsignedHeaders = make(http.Header)
	for k, v := range ctx.Header {
		lowerCaseKey := strings.ToLower(k)
		if !shouldSign(lowerCaseKey, ctx.signedHeaderKeys) {
			continue // ignored header
		}
		unsignedHeaders.Set(k, strings.Join(v, ""))
	}
	var headers []string
	for k, v := range unsignedHeaders {
		canonicalKey := http.CanonicalHeaderKey(k)
		if shouldIgnore(canonicalKey, ignoredHeaders) {
			continue // ignored header
		}
		if ctx.SignedHeaderVals == nil {
			ctx.SignedHeaderVals = make(http.Header)
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := ctx.SignedHeaderVals[lowerCaseKey]; ok {
			// include additional values
			ctx.SignedHeaderVals[lowerCaseKey] = append(ctx.SignedHeaderVals[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		ctx.SignedHeaderVals[lowerCaseKey] = v
	}
	sort.Strings(headers)

	ctx.signedHeaders = strings.Join(headers, ";")

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		if k == "host" {
			headerValues[i] = "host:" + ctx.Host
		} else {
			headerValues[i] = k + ":" +
				strings.Join(ctx.SignedHeaderVals[k], ",")
		}
	}
	stripExcessSpaces(headerValues)
	ctx.canonicalHeaders = strings.Join(headerValues, "\n")
}

func (ctx *signingCtx) buildCanonicalString() {
	ctx.canonicalString = strings.Join([]string{
		ctx.Method,
		ctx.Path,
		ctx.RawQuery,
		ctx.canonicalHeaders + "\n",
		ctx.signedHeaders,
		ctx.bodyDigest,
	}, "\n")
}

func (ctx *signingCtx) buildStringToSign() {
	ctx.stringToSign = strings.Join([]string{
		authHeaderPrefix,
		ctx.formattedTime,
		ctx.credentialString,
		hex.EncodeToString(makeSha256([]byte(ctx.canonicalString))),
	}, "\n")
}

func (ctx *signingCtx) buildSignature() {
	secret := ctx.credValues.SecretKey
	date := makeHmac([]byte("JDCLOUD2"+secret), []byte(ctx.formattedShortTime))
	region := makeHmac(date, []byte(ctx.Region))
	service := makeHmac(region, []byte(ctx.ServiceName))
	credentials := makeHmac(service, []byte("jdcloud2_request"))
	signature := makeHmac(credentials, []byte(ctx.stringToSign))
	ctx.signature = hex.EncodeToString(signature)
}

func (ctx *signingCtx) buildBodyDigest() {
	if ctx.Header.Get(headerJdcloudContentSha256) != "" {
		ctx.bodyDigest = ctx.Header.Get(headerJdcloudContentSha256)
		return
	}
	var hash string
	if ctx.Body == "" {
		hash = emptyStringSHA256
	} else {
		hash = hex.EncodeToString(makeSha256Content(ctx.Body))
	}
	ctx.bodyDigest = hash
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func makeSha256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func makeSha256Content(content string) []byte {
	hash := sha256.New()
	hash.Write([]byte(content))
	return hash.Sum(nil)
}

const doubleSpace = "  "

// stripExcessSpaces will rewrite the passed in slice's string values to not
// contain muliple side-by-side spaces.
func stripExcessSpaces(vals []string) {
	var j, k, l, m, spaces int
	for i, str := range vals {
		// Trim trailing spaces
		for j = len(str) - 1; j >= 0 && str[j] == ' '; j-- {
		}

		// Trim leading spaces
		for k = 0; k < j && str[k] == ' '; k++ {
		}
		str = str[k : j+1]

		// Strip multiple spaces.
		j = strings.Index(str, doubleSpace)
		if j < 0 {
			vals[i] = str
			continue
		}

		buf := []byte(str)
		for k, m, l = j, j, len(buf); k < l; k++ {
			if buf[k] == ' ' {
				if spaces == 0 {
					// First space.
					buf[m] = buf[k]
					m++
				}
				spaces++
			} else {
				// End of multiple spaces.
				spaces = 0
				buf[m] = buf[k]
				m++
			}
		}

		vals[i] = string(buf[:m])
	}
}

func getURIPath(u *url.URL) string {
	var path string

	if len(u.Opaque) > 0 {
		path = "/" + strings.Join(strings.Split(u.Opaque, "/")[3:], "/")
	} else {
		path = u.EscapedPath()
	}

	if len(path) == 0 {
		path = "/"
	}

	return path
}

func shouldIgnore(header string, ignoreHeaders []string) bool {
	for _, v := range ignoreHeaders {
		if v == header {
			return true
		}
	}
	return false
}

func shouldSign(header string, signHeaders []string) bool {
	for _, v := range signHeaders {
		if v == header {
			return true
		}
	}
	return false
}

// EscapePath escapes part of a URL path
func EscapePath(path string, encodeSep bool) string {
	var buf bytes.Buffer
	for i := 0; i < len(path); i++ {
		c := path[i]
		if noEscape[c] || (c == '/' && !encodeSep) {
			buf.WriteByte(c)
		} else {
			fmt.Fprintf(&buf, "%%%02X", c)
		}
	}
	return buf.String()
}
