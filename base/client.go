package base

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	// 本地库
	"updateCFIP/config"

	// 第三方库
	resty "github.com/imroc/req/v3"
	"github.com/sirupsen/logrus"
)

type ClientParams struct {
	UserAgent        string
	DisAllowRedirect bool
	DownloadMode     bool
}

func NewRestyClient(params ClientParams) *resty.Client {
	client := resty.C().
		SetTimeout(0).
		SetCommonRetryBackoffInterval(100*time.Millisecond, 3*time.Second).
		SetTLSClientConfig(&tls.Config{
			InsecureSkipVerify: true,
		}).
		AddCommonRetryCondition(func(resp *resty.Response, err error) bool {
			if err != nil && !errors.Is(err, context.Canceled) {
				logrus.Warnf("client 请求失败, 错误: %+v, 请求头: %+v.", err, resp.Request.Headers)
				return true
			}
			if params.DownloadMode {
				if resp != nil && !resp.IsSuccessState() {
					logrus.Warnf("client 请求失败, 状态码: %d, 请求头: %+v.", resp.StatusCode, resp.Request.Headers)
					return true
				}
			}
			return false
		})

	// 自定义 DNS 解析器
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	resolver := new(net.Resolver)
	preferIPV := config.GetPreferIPV()
	dns, port := config.GetDns(preferIPV)
	if port != "" {
		dns = net.JoinHostPort(dns, port)
	}
	// 判断 DNS 是否为空，如果为空则不执行后续代码
	if dns != "" {
		resolver.PreferGo = true
		resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			if port == "" && !strings.Contains(dns, ":53") {
				dns += ":53"
			}
			return dialer.DialContext(ctx, network, dns)
		}
	}

	if preferIPV == "ipv4" || preferIPV == "ipv6" {
		userDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := resolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if (preferIPV == "ipv4" && ip.To4() != nil) || (preferIPV == "ipv6" && ip.To16() != nil && ip.To4() == nil) {
					host = ip.String()
					break
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		}
		client.SetDial(userDialer)
	} else {
		dialer.Resolver = resolver
		client.SetDial(dialer.DialContext)
	}

	client.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: true, // 忽略证书验证
	})
	client.SetResponseHeaderTimeout(30 * time.Second)
	client.SetIdleConnTimeout(30 * time.Second)

	if params.UserAgent != "" {
		SetTLSFingerprint(client, params.UserAgent)
	}
	if params.DisAllowRedirect {
		client.SetRedirectPolicy(resty.NoRedirectPolicy())
	}
	return client
}

func SetTLSFingerprint(client *resty.Client, userAgent string) {
	userAgent = strings.ToLower(userAgent)
	switch {
	case strings.Contains(userAgent, "edge"):
		client.ImpersonateChrome()
		//client.SetTLSFingerprintEdge()
	case strings.Contains(userAgent, "chrome"):
		client.ImpersonateChrome()
		//client.SetTLSFingerprintChrome()
	case strings.Contains(userAgent, "android"):
		client.ImpersonateChrome()
		//client.SetTLSFingerprintAndroid()
	case strings.Contains(userAgent, "firefox"):
		client.ImpersonateFirefox()
		//client.SetTLSFingerprintFirefox()
	case strings.Contains(userAgent, "mac os"):
		client.ImpersonateSafari()
		//client.SetTLSFingerprintSafari()
	default:
		client.ImpersonateChrome()
		//client.SetTLSFingerprintRandomized()
	}
}
