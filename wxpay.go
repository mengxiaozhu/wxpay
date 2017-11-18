package wxpay

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"io/ioutil"
	"math/rand"
	"sort"
	"strings"
	"time"

	"encoding/hex"
	"errors"
	"github.com/cocotyty/httpclient"
	"net"
	"net/http"
	"reflect"
)

const (
	HOST               = "https://api.mch.weixin.qq.com"
	SANDBOX            = "/sandbox"
	TransfersPath      = "/mmpaymkttransfers/promotion/transfers"
	TransfersQueryPath = "mmpaymkttransfers/gettransferinfo"
)

type Client struct {
	AppID           string
	MchID           string
	ApiKey          string
	PrivateKeyFile  string
	CertificateFile string
	CAFile          string
	SandBox         bool
	config          *tls.Config
	client          *http.Client
}

func (c *Client) Init() {
	c.config = c.mustGetTlsConfiguration()
	c.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: c.config,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// 企业向个人转账的订单查询 请求
type CompanyTransferQueryRequest struct {
	PartnerTradeNo string `xml:"partner_trade_no"` //partner_trade_no
}

// 企业向个人转账的订单查询 响应
type CompanyTransferQueryResponse struct {
	ResultCode     string `xml:"result_code"`      // 业务结果 	是	SUCCESS	String(16)	SUCCESS/FAIL
	ErrCode        string `xml:"err_code"`         // 错误代码 	否	SYSTEMERROR	String(32)	错误码信息
	ErrCodeDes     string `xml:"err_code_des"`     // 错误代码描述 	否	系统错误	String(128)	结果信息描述
	PartnerTradeNo string `xml:"partner_trade_no"` // 商户单号 	是	10000098201411111234567890	String(28)	商户使用查询API填写的单号的原路返回.
	MchId          string `xml:"mch_id"`           // 商户号 	是	10000098	String(32)	微信支付分配的商户号
	DetailId       string `xml:"detail_id"`        // 付款单号 	是	1000000000201503283103439304	String(32)	调用企业付款API时，微信系统内部产生的单号
	Status         string `xml:"status"`           // 转账状态 	是	SUCCESS	string(16)
	Reason         string `xml:"reason"`           // 失败原因 	否	余额不足	String	如果失败则有失败原因
	Openid         string `xml:"openid"`           // 收款用户openid 	是	oxTWIuGaIt6gTKsQRLau2M0yL16E	 	转账的openid
	TransferName   string `xml:"transfer_name"`    // 收款用户姓名 	否	马华	String	收款用户姓名
	PaymentAmount  string `xml:"payment_amount"`   // 付款金额 	是	5000	int	付款金额单位分）
	TransferTime   string `xml:"transfer_time"`    // 转账时间 	是	2015-04-21 20:00:00	String	发起转账的时间
	Desc           string `xml:"desc"`             // 付款描述 	是	车险理赔	String	付款时候的描述
}
type CompanyTransferRequest struct {
	BaseRequest
	PartnerTradeNo string `xml:"partner_trade_no"`
	Openid         string `xml:"openid"`
	CheckName      string `xml:"check_name"`
	ReUserName     string `xml:"re_user_name"`
	Amount         string `xml:"amount"`
	Desc           string `xml:"desc"`
	SpbillCreateIp string `xml:"spbill_create_ip"`
}

type CompanyTransferResponse struct {
	XMLName        xml.Name `xml:"xml"`
	ReturnCode     string   `xml:"return_code"`
	ReturnMsg      string   `xml:"return_msg"`
	ResultCode     string   `xml:"result_code"`
	ErrCode        string   `xml:"err_code"`
	ErrCodeDes     string   `xml:"err_code_des"`
	PartnerTradeNo string   `xml:"partner_trade_no"`
	PaymentNo      string   `xml:"payment_no"`
	PaymentTime    string   `xml:"payment_time"`
}

func (c *Client) request() *BaseRequest {
	return &BaseRequest{
		AppID:    c.AppID,
		MchID:    c.MchID,
		NonceStr: getNonceStr(),
		appKey:   c.ApiKey,
	}
}

func (c *Client) CompanyTransfer(req *CompanyTransferRequest) (*CompanyTransferResponse, error) {
	data, err := c.send(TransfersPath, req)
	if err != nil {
		return nil, err
	}
	resp := &CompanyTransferResponse{}
	err = xml.Unmarshal(data, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) CompanyTransferQuery(req *CompanyTransferQueryRequest) (*CompanyTransferQueryResponse, error) {
	data, err := c.send(TransfersQueryPath, req)
	if err != nil {
		return nil, err
	}
	resp := &CompanyTransferQueryResponse{}
	err = xml.Unmarshal(data, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) send(path string, req interface{}) ([]byte, error) {
	url := HOST
	if c.SandBox {
		url += SANDBOX
	}
	url += TransfersPath

	c.signRequest(req)

	data, err := xml.Marshal(req)
	if err != nil {
		return nil, err
	}

	return httpclient.New(c.client).Post(url).Body(data).Send().Body()
}
func (c *Client) mustLoadCertificates() (tls.Certificate, *x509.CertPool) {
	privateKeyFile := c.PrivateKeyFile
	certificateFile := c.CertificateFile
	caFile := c.CAFile

	mycert, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		panic(err)
	}

	pem, err := ioutil.ReadFile(caFile)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		panic("Failed appending certs")
	}

	return mycert, certPool

}

func (c *Client) mustGetTlsConfiguration() *tls.Config {
	config := &tls.Config{}
	mycert, certPool := c.mustLoadCertificates()
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0] = mycert

	config.RootCAs = certPool
	config.ClientCAs = certPool

	config.ClientAuth = tls.RequireAndVerifyClientCert

	//Optional stuff

	//Use only modern ciphers
	config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	//Use only TLS v1.2
	config.MinVersion = tls.VersionTLS12

	//Don't allow session resumption
	config.SessionTicketsDisabled = true
	return config
}

var reqType = reflect.TypeOf(&BaseRequest{})

func (c *Client) signRequest(request interface{}) error {
	val := reflect.ValueOf(request)

	for val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return errors.New("must struct")
	}

	typ := val.Type()
	keys := make([]string, 0, typ.NumField()+2)
	values := map[string]string{}
	req := c.request()
	hasRequestField := false
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Anonymous && f.Type == reqType {
			val.Field(i).Set(reflect.ValueOf(req))
			values["mch_appid"] = req.AppID
			values["mch_id"] = req.MchID
			hasRequestField = true
		}

		name := strings.Split(typ.Field(i).Tag.Get("xml"), ",")[0]
		if name == "" {
			continue
		}
		keys = append(keys, name)
		values[name] = val.Field(i).Interface().(string)
	}
	if !hasRequestField {
		return errors.New("must extend from BaseRequest")
	}
	sort.Strings(keys)
	bf := bytes.NewBuffer(nil)
	for _, v := range keys {
		bf.WriteString(v)
		bf.WriteByte('=')
		bf.WriteString(values[v])
		bf.WriteByte('&')
	}
	bf.WriteString("key=")
	bf.WriteString(req.appKey)

	req.Sign = hex.EncodeToString(md5.Sum(bf.Bytes())[:])
	return nil
}

//获取32位长度的随机数
func getNonceStr() (nonceStr string) {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 32; i++ {
		idx := rand.Intn(len(chars) - 1)
		nonceStr += chars[idx : idx+1]
	}
	return
}

const (
	ReturnCodeSuccess = "FAIL"
	ReturnCodeFail    = "SUCCESS"
)
const (
	ErrCode_NO_AUTH               = "NO_AUTH"                //没有该接口权限	没有授权请求此api	请关注是否满足接口调用条件
	ErrCode_AMOUNT_LIMIT          = "AMOUNT_LIMIT"           //付款金额不能小于最低限额	付款金额不能小于最低限额	每次付款金额必须大于1元 付款失败，因你已违反《微信支付商户平台使用协议》，单笔单次付款下限已被调整为5元	商户号存在违反协议内容行为，单次付款下限提高	请遵守《微信支付商户平台使用协议》
	ErrCode_PARAM_ERROR           = "PARAM_ERROR"            //参数错误	参数缺失，或参数格式出错，参数不合法等	请查看err_code_des，修改设置错误的参数
	ErrCode_OPENID_ERROR          = "OPENID_ERROR"           //Openid错误	Openid格式错误或者不属于商家公众账号	请核对商户自身公众号appid和用户在此公众号下的openid。
	ErrCode_SEND_FAILED           = "SEND_FAILED"            //付款错误	付款失败，请换单号重试	付款失败，请换单号重试
	ErrCode_NOTENOUGH             = "NOTENOUGH"              //余额不足	帐号余额不足	请用户充值或更换支付卡后再支付
	ErrCode_SYSTEMERROR           = "SYSTEMERROR"            //系统繁忙，请稍后再试。	系统错误，请重试	请使用原单号以及原请求参数重试，否则可能造成重复支付等资金风险
	ErrCode_NAME_MISMATCH         = "NAME_MISMATCH"          //姓名校验出错	请求参数里填写了需要检验姓名，但是输入了错误的姓名	填写正确的用户姓名
	ErrCode_SIGN_ERROR            = "SIGN_ERROR"             //签名错误	没有按照文档要求进行签名 签名前没有按照要求进行排序。 没有使用商户平台设置的密钥进行签名 参数有空格或者进行了encode后进行签名。
	ErrCode_XML_ERROR             = "XML_ERROR"              //Post内容出错	Post请求数据不是合法的xml格式内容	修改post的内容
	ErrCode_FATAL_ERROR           = "FATAL_ERROR"            //两次请求参数不一致	两次请求商户单号一样，但是参数不一致	如果想重试前一次的请求，请用原参数重试，如果重新发送，请更换单号。
	ErrCode_FREQ_LIMIT            = "FREQ_LIMIT"             //超过频率限制，请稍后再试。	接口请求频率超时接口限制	请关注接口的使用条件
	ErrCode_MONEY_LIMIT           = "MONEY_LIMIT"            //已经达到今日付款总额上限/已达到付款给此用户额度上限	接口对商户号的每日付款总额，以及付款给同一个用户的总额有限制	请关注接口的付款限额条件
	ErrCode_CA_ERROR              = "CA_ERROR"               //证书出错	请求没带证书或者带上了错误的证书 到商户平台下载证书 请求的时候带上该证书 V2
	ErrCode_V2_ACCOUNT_SIMPLE_BAN = "V2_ACCOUNT_SIMPLE_BAN	" //无法给非实名用户付款	用户微信支付账户未知名，无法付款	引导用户在微信支付内进行绑卡实名
	ErrCode_PARAM_IS_NOT_UTF8     = "PARAM_IS_NOT_UTF8"      //请求参数中包含非utf8编码字符	接口规范要求所有请求参数都必须为utf8编码	请关注接口使用规范
)
