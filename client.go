package soopay

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/PuerkitoBio/goquery"
	"github.com/qiniu/iconv"
)

// Client 联动支付客户端
type Client struct {
	gateway string
	mchID   string
	prvKey  *PrivateKey
	pubKey  *PublicKey
	httpCli HTTPClient
	logger  func(ctx context.Context, data map[string]string)
}

// MchNO 返回商户编号
func (c *Client) MchID() string {
	return c.mchID
}

// Encrypt 敏感数据RSA加密
func (c *Client) Encrypt(plain string) (string, error) {
	if c.pubKey == nil {
		return "", errors.New("public key is nil (forgotten configure?)")
	}

	b, err := c.pubKey.Encrypt([]byte(plain))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// MustEncrypt 敏感数据RSA加密；若发生错误，则Panic
func (c *Client) MustEncrypt(plain string) string {
	if c.pubKey == nil {
		panic(errors.New("public key is nil (forgotten configure?)"))
	}

	b, err := c.pubKey.Encrypt([]byte(plain))
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(b)
}

// Decrypt 敏感数据RSA解密
func (c *Client) Decrypt(cipher string) (string, error) {
	if c.prvKey == nil {
		return "", errors.New("private key is nil (forgotten configure?)")
	}

	b, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return "", err
	}

	plain, err := c.prvKey.Decrypt(b)
	if err != nil {
		return "", err
	}

	// convert gbk to utf-8
	cd, err := iconv.Open("utf-8", "gbk")
	if err != nil {
		return "", err
	}
	defer cd.Close()

	return cd.ConvString(string(plain)), nil
}

// Do 发送请求
func (c *Client) Do(ctx context.Context, service string, bizData V) (V, error) {
	log := NewReqLog(http.MethodPost, c.gateway)
	defer log.Do(ctx, c.logger)

	form, err := c.reqForm(service, bizData)
	if err != nil {
		return nil, err
	}

	log.SetReqBody(form)

	resp, err := c.httpCli.Do(ctx, http.MethodPost, c.gateway, []byte(form))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

	return c.VerifyHTML(b)
}

func (c *Client) reqForm(service string, bizData V) (string, error) {
	if c.prvKey == nil {
		return "", errors.New("private key is nil (forgotten configure?)")
	}

	bizData.Set("service", service)
	bizData.Set("charset", "UTF-8")
	bizData.Set("sign_type", "RSA")
	bizData.Set("res_format", "HTML")
	bizData.Set("version", "4.0")
	bizData.Set("mer_id", c.mchID)

	signStr := bizData.Encode("=", "&", WithEmptyMode(EmptyIgnore), WithIgnoreKeys("sign", "sign_type"))

	sign, err := c.prvKey.Sign(crypto.SHA1, []byte(signStr))
	if err != nil {
		return "", err
	}

	bizData.Set("sign", base64.StdEncoding.EncodeToString(sign))

	return bizData.Encode("=", "&", WithEmptyMode(EmptyIgnore)), nil
}

func (c *Client) VerifyHTML(body []byte) (V, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	content, ok := doc.Find("meta[name='MobilePayPlatform']").Attr("content")
	if !ok || len(content) == 0 {
		return nil, errors.New("err empty meta content")
	}

	vals, err := url.ParseQuery(content)
	if err != nil {
		return nil, err
	}

	return c.VerifyQuery(vals)
}

func (c *Client) VerifyQuery(vals url.Values) (V, error) {
	if c.pubKey == nil {
		return nil, errors.New("public key is nil (forgotten configure?)")
	}

	ret := V{}
	for k, vs := range vals {
		if len(vs) != 0 {
			ret.Set(k, vs[0])
		}
	}

	signStr := ret.Encode("=", "&", WithIgnoreKeys("sign", "sign_type"))

	if err := c.pubKey.Verify(crypto.SHA256, []byte(signStr), []byte(ret["sign"])); err != nil {
		return nil, err
	}

	return ret, nil
}

// ReplyHTML 通知相应
func (c *Client) ReplyHTML(data V) (string, error) {
	if c.prvKey == nil {
		return "", errors.New("private key is nil (forgotten configure?)")
	}

	data.Set("mer_id", c.mchID)
	data.Set("sign_type", "RSA")
	data.Set("version", "4.0")

	signStr := data.Encode("=", "&", WithEmptyMode(EmptyIgnore), WithIgnoreKeys("sign", "sign_type"))

	sign, err := c.prvKey.Sign(crypto.SHA256, []byte(signStr))
	if err != nil {
		return "", err
	}

	data.Set("sign", base64.StdEncoding.EncodeToString(sign))

	html := fmt.Sprintf(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><html><head><META NAME="MobilePayPlatform" CONTENT="%s"/></head><body></body></html>`, data.Encode("=", "&", WithEmptyMode(EmptyIgnore)))

	return html, nil
}

// Option 自定义设置项
type Option func(c *Client)

// WithHttpCli 设置自定义 HTTP Client
func WithHttpCli(cli *http.Client) Option {
	return func(c *Client) {
		c.httpCli = NewHTTPClient(cli)
	}
}

// WithPrivateKey 设置商户RSA私钥
func WithPrivateKey(key *PrivateKey) Option {
	return func(c *Client) {
		c.prvKey = key
	}
}

// WithPublicKey 设置平台RSA公钥
func WithPublicKey(key *PublicKey) Option {
	return func(c *Client) {
		c.pubKey = key
	}
}

// WithLogger 设置日志记录
func WithLogger(f func(ctx context.Context, data map[string]string)) Option {
	return func(c *Client) {
		c.logger = f
	}
}

// NewClient 生成银盛支付客户端
func NewClient(mchID string, options ...Option) *Client {
	c := &Client{
		gateway: "https://pay.soopay.net/spay/pay/payservice.do",
		mchID:   mchID,
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c
}
