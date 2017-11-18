package wxpay

import "encoding/xml"

type BaseRequest struct {
	XMLName  xml.Name `xml:"xml"`
	Sign     string   `xml:"sign"`
	AppID    string   `xml:"mch_appid"`
	MchID    string   `xml:"mch_id"`
	NonceStr string   `xml:"nonce_str"`
	appKey   string
}
