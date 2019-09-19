# 京东云Golang SDK
欢迎使用京东云API网关开发者Golang工具套件（Go Signature SDK）。使用京东云API网关Go Signature SDK，您无需复杂编程就可以访问京东云API网关API提供者提供的各种服务。
为了方便您理解SDK中的一些概念和参数的含义，使用SDK前建议您先查看京东云API网关使用入门。

## 环境准备
1.	京东云API网关Go Signature SDK适用于Go 1.6及以上版本。
2.	在开始调用京东云API网关之前，需提前联系API提供者生成或绑定访问密钥，如果API提供者提供的接口为免鉴权，则无需使用该SDK。

## 下载和安装
在项目路径下(GOPATH)执行以下命令：
```
GOPATH=$(PWD)
mkdir -p src/git.jd.com/jcloud-api-gateway/jdcloud-apigateway-signature-go
cd src/git.jd.com/jcloud-api-gateway/jdcloud-apigateway-signature-go
go get -insecure git.jd.com/jcloud-api-gateway/jdcloud-apigateway-signature-go/core github.com/gofrs/uuid
```

或手工下载压缩包，最终目录结构为：
`$GOPATH/src/git.jd.com/jcloud-api-gateway/jdcloud-apigateway-signature-go`

## 调用SDK
### 业务侧SDK的调用主要分为4步：
1.	设置accessKey和secretKey
2.	创建Logger
3.	设置域名、URI、请求方式、header和请求参数，header必须包含：x-jdcloud-nonce、x-jdcloud-date(格式：20190101T010101Z)、content-type
4.	执行方法得到签名并放到header中

### 大致代码如下：
``` go
var header = make(http.Header)
nonce, _ := uuid.NewV4()
header.Set(core.HeaderJdcloudNonce, nonce.String())
time := time.Now()
formattedTime := time.UTC().Format(TimeFormat)
header.Set(HeaderJdcloudDate, formattedTime)
header.Set("content-type", "application/json");

Credential := *NewCredentials("ak", "sk")
Logger := NewDefaultLogger(3)
signer := NewSigner(Credential, Logger)
sign, _ := signer.Sign("xit7hp4yw8vn.cn-north-1.jdcloud-api.net:8000", "/test","POST", header,nil, "")
header.Set(HeaderJdcloudAuthorization, sign)
```
请参考sign_test中的测试用例，访问京东云API网关API提供方的接口。
