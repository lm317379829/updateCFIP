package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"updateCFIP/config"

	"updateCFIP/base"

	log "github.com/sirupsen/logrus"
)

type ZoneInfos struct {
	Result []struct {
		ID string `json:"id"`
	} `json:"result"`
}

type DNSInfos struct {
	Result []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		RemortIP string `json:"content"`
		Proxy    bool   `json:"proxied"`
	} `json:"result"`
}

type Result struct {
	Success bool `json:"success"`
	Error   []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
}

func handleMain(key, email, domain string) {
	content := ""

	// 设置请求头
	header := map[string]string{
		"Accept":     "application/json",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36",
	}

	clientParams := base.ClientParams{
		UserAgent: header["User-Agent"],
	}
	client := base.NewRestyClient(clientParams).SetCommonRetryCount(3).SetCommonHeaders(header)

	defer func() {
		content = strings.TrimSpace(content)
		Tele := config.GetTele()
		if Tele.Update && content != "" && Tele.Url != "" && Tele.ID != "" {
			// 更新IP到指定URL
			params := map[string]any{
				"chat_id": Tele.ID,
				"text":    content,
			}
			header := map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36",
			}

			url := Tele.Url
			resp, err := client.R().
				SetHeaders(header).
				SetBody(params).
				Post(url)

			if err != nil {
				log.Errorf("更新 IP 到 Telegram 错误: %+v", err)
				return
			}
			log.Infof("更新 IP 到 Telegram 成功: %s", content)

			err = resp.Body.Close()
			if err != nil {
				log.Errorf("关闭响应体错误: %+v", err)
			}
		}
	}()

	localIP := ""
	ipv4, err := getExternalIPv4()
	if err != nil {
		log.Debugf("获取IPv4地址失败: %+v", err)
	}
	ipv6, err := getExternalIPv6()
	if err != nil {
		log.Debugf("获取IPv6地址失败: %+v", err)
	}
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", domain)
	var zoneInfos ZoneInfos
	resp, err := client.R().
		SetHeader("X-Auth-Email", email).
		SetHeader("X-Auth-Key", key).
		SetSuccessResult(&zoneInfos).
		Get(url)

	if err != nil {
		log.Errorf("获取根域名 %s 的 ZoneName 错误: %+v", domain, err)
		content = fmt.Sprintf("获取根域名 %s 的 ZoneName 错误: %+v", domain, err)
		return
	}

	err = resp.Body.Close()
	if err != nil {
		log.Errorf("关闭响应体错误: %+v", err)
	}

	if len(zoneInfos.Result) == 0 {
		log.Warnf("未找到域名 %s 的 ZoneName", domain)
		content = fmt.Sprintf("未找到域名 %s 的 ZoneName", domain)
		return
	}

	zid := ""
	if len(zoneInfos.Result) > 0 {
		zid = zoneInfos.Result[0].ID
		if zid == "" {
			log.Warnf("未找到域名 %s 的 ZoneID", domain)
			content = fmt.Sprintf("未找到域名 %s 的 ZoneID", domain)
			return
		}
	}

	subs := config.GetSubs()
	for _, sub := range subs {
		name := sub.Name

		cates := sub.Cates
		for _, cate := range cates {
			cate := strings.TrimSpace(cate)
			switch cate {
			case "A":
				if ipv4 == "" {
					continue
				}
				localIP = ipv4
			case "AAAA":
				if ipv6 == "" {
					continue
				}
				localIP = ipv6
			default:
				log.Warnf("不支持的 DNS 类型 %s, 仅支持 ipv4-A、ipv6-AAAA", cate)
				continue
			}

			localIPContent := fmt.Sprintf("域名 %s.%s 的 IP 应为 %s\n", name, domain, localIP)

			url = fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s.%s", zid, name, domain)
			var dnsInfos DNSInfos
			resp, err = client.R().
				SetHeader("X-Auth-Email", email).
				SetHeader("X-Auth-Key", key).
				SetSuccessResult(&dnsInfos).
				Get(url)

			if err != nil {
				log.Warnf("获取域名 %s.%s 的 DNS 记录错误: %s", name, domain, err)
				content += localIPContent
				continue
			}
			err = resp.Body.Close()
			if err != nil {
				log.Errorf("关闭响应体错误: %+v", err)
			}

			rid := ""
			remortIP := ""
			proxied := false
			for _, record := range dnsInfos.Result {
				if record.Type == cate {
					rid = record.ID
					remortIP = record.RemortIP
					proxied = record.Proxy
					break
				}
			}

			if rid == "" || remortIP == "" {
				log.Error("错误: 未获取到 Rid 或 RemortIP")
				content += localIPContent
				continue
			}

			if localIP != remortIP {
				content += localIPContent
				params := map[string]interface{}{
					"id":      zid,
					"type":    cate,
					"name":    fmt.Sprintf("%s.%s", name, domain),
					"content": localIP,
					"proxied": proxied,
				}

				url = fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zid, rid)

				var result Result
				resp, err = client.R().
					SetHeader("X-Auth-Email", email).
					SetHeader("X-Auth-Key", key).
					SetSuccessResult(&result).
					SetBody(params).
					Put(url)

				if err != nil {
					log.Errorf("域名 %s.%s 更新错误: %+v", name, domain, err)
					continue
				}
				err = resp.Body.Close()
				if err != nil {
					log.Errorf("关闭响应体错误: %+v", err)
				}
				if !result.Success {
					for _, erro := range result.Error {
						log.Errorf("域名 %s.%s 更新错误: %s", name, domain, erro.Message)
						content += fmt.Sprintf("域名 %s.%s 更新错误: %s\n", name, domain, erro.Message)
					}
					content += localIPContent
				} else {
					log.Infof("域名 %s.%s 的IP已更新为 %s", name, domain, localIP)
					content += fmt.Sprintf("域名 %s.%s 的IP已更新为 %s\n", name, domain, localIP)
				}
			} else {
				log.Infof("域名 %s.%s 的IP为 %s 未改变, 无需更新", name, domain, localIP)
				err = resp.Body.Close()
				if err != nil {
					log.Errorf("关闭响应体错误: %+v", err)
				}
				continue
			}
		}
	}
}

// 获取外网IPv4地址
func getExternalIPv4() (string, error) {
	// 连接到一个外部IPv4地址，这里使用Google的DNS服务器
	ipv4 := config.GetDns("ipv4")
	if ipv4 == "" {
		ipv4 = "223.5.5.5"
	}
	conn, err := net.Dial("tcp4", fmt.Sprintf("%s:80", ipv4))
	if err != nil {
		return "", err
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Errorf("关闭连接错误: %+v", err)
		}
	}()

	// 获取本地地址信息
	localAddr := conn.LocalAddr().String()
	// 分割IP和端口
	ip := strings.Split(localAddr, ":")[0]
	return ip, nil
}

// 获取外网IPv6地址
func getExternalIPv6() (string, error) {
	// 连接到一个外部IPv6地址，这里使用Google的IPv6 DNS服务器
	ipv6 := config.GetDns("ipv6")
	if ipv6 == "" {
		ipv6 = "[2400:3200::1]"
	}
	conn, err := net.Dial("tcp6", fmt.Sprintf("%s:80", ipv6))
	if err != nil {
		return "", err
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Errorf("关闭连接错误: %+v", err)
		}
	}()

	// 获取本地地址信息
	localAddr := conn.LocalAddr().String()
	// 分割IP和端口，IPv6地址格式为[ipv6]:port
	re := regexp.MustCompile(`^\[([a-fA-F0-9:]+)\]:\d+$`)
	matches := re.FindStringSubmatch(localAddr)
	if len(matches) != 2 {
		return "", fmt.Errorf("无法解析IPv6地址")
	}
	ip := matches[1]
	return ip, nil
}

func main() {
	// 定义命令行参数
	filePath := flag.String("file", "config.json", "文件路径和名称")
	// 加载配置文件和命令行参数
	err := config.LoadConfig(*filePath)
	if err != nil {
		log.Warnf("无法加载配置文件，错误: %+v", err)
	}

	// 解析命令行参数
	flag.Parse()

	key := config.GetKey()
	email := config.GetEmail()
	domain := config.GetDomain()
	if key == "" || email == "" || domain == "" {
		log.Fatalf("配置文件缺少必要的字段: Key, Email 或 Domain")
	}

	// 设置日志输出
	log.SetOutput(os.Stdout)
	if config.GetDebug() {
		log.SetLevel(log.DebugLevel)
		log.Debug("调试模式已启用")
	} else {
		log.SetLevel(log.InfoLevel)
	}

	handleMain(key, email, domain)
}
