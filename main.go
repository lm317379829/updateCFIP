package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	Key         string     `json:"key"`
	Email       string     `json:"email"`
	DomainInfos [][]string `json:"domainInfos"`
	Telegram    struct {
		Update bool   `json:"update"`
		Url    string `json:"url"`
		ID     string `json:"id"`
	} `json:"telegram,omitempty"`
}

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

func retryRequest(method, url string, params map[string]any, header map[string]string) (*http.Response, error) {
	maxRetries := 5               // 最大重试次数
	retryDelay := 2 * time.Second // 重试间隔时间

	var err error
	var req *http.Request
	var resp *http.Response
	client := &http.Client{
		Timeout: 30 * time.Second, // 设置超时时间为 30 秒
	}

	for count := 0; count < maxRetries; count++ {
		switch method {
		case http.MethodGet:
			req, err = http.NewRequest(http.MethodGet, url, nil)
		case http.MethodPut, http.MethodPost:
			body, erro := json.Marshal(params)
			if erro != nil {
				log.Errorf("错误: %+v", erro)
				return nil, fmt.Errorf("格式化请求体错误: %+v", erro)
			}
			bodyBuffer := bytes.NewBuffer(body)
			contentLength := strconv.Itoa(bodyBuffer.Len())
			header["Content-Length"] = contentLength
			req, err = http.NewRequest(method, url, bodyBuffer)
		default:
			return nil, fmt.Errorf("不支持的 Method: %s", method)
		}

		if err != nil {
			log.Infof("错误: %+v", err)
			return nil, fmt.Errorf("错误: %+v", err)
		}

		for key, value := range header {
			req.Header.Set(key, value)
		}

		resp, err = client.Do(req)
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
			// 请求失败，等待重试
			if resp != nil {
				defer resp.Body.Close()
			}
			log.Warnf("请求 %s 失败, 等待 %ds 后重试", url, retryDelay/1000000000)
			time.Sleep(retryDelay)
			continue
		} else {
			// 请求成功，返回响应
			return resp, nil
		}
	}

	switch {
	case err != nil:
		return nil, fmt.Errorf("访问 %s 失败: %+v", url, err)
	case resp != nil && (resp.StatusCode < 200 || resp.StatusCode >= 400):
		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("访问 %s 失败: %d", url, resp.StatusCode)
		}
		respString := strings.TrimSpace(string(responseBody))
		if respString != "" {
			return nil, fmt.Errorf("访问 %s 失败: %d\n%s", url, resp.StatusCode, respString)
		} else {
			return nil, fmt.Errorf("访问 %s 失败: %d", url, resp.StatusCode)
		}
	default:
		return nil, fmt.Errorf("访问 %s 失败", url)
	}
}

func handleMain(config Config) {
	content := ""

	// 设置请求头
	header := map[string]string{
		"X-Auth-Key":   config.Key,
		"X-Auth-Email": config.Email,
		"Accept":       "application/json",
		"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36",
	}

	defer func() {
		content = strings.TrimSpace(content)
		if config.Telegram.Update && content != "" && config.Telegram.Url != "" && config.Telegram.ID != "" {
			// 更新IP到指定URL
			params := map[string]any{
				"chat_id": config.Telegram.ID,
				"text":    content,
			}
			header := map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36",
			}
			_, err := retryRequest("POST", config.Telegram.Url, params, header)
			if err != nil {
				log.Errorf("更新 IP 到 Telegram 错误: %+v", err)
			}
			log.Infof("更新 IP 到 Telegram 成功: %s", content)
		}
	}()

	for _, domainInfo := range config.DomainInfos {
		var err error
		var resp *http.Response
		var responseBody []byte
		name := domainInfo[0]
		domain := domainInfo[1]

		dnsTypes := strings.Split(domainInfo[2], ",")
		for _, dnsType := range dnsTypes {
			dnsType := strings.TrimSpace(dnsType)
			if dnsType == "A" {
				resp, err = retryRequest("GET", "http://4.ipw.cn", nil, header)
				if err != nil {
					log.Warnf("获取 IPV4 地址错误: %+v", err)
					return
				}
			} else if dnsType == "AAAA" {
				resp, err = retryRequest("GET", "http://6.ipw.cn", nil, header)
				if err != nil {
					log.Warnf("获取 IPV6 地址错误: %+v", err)
					return
				}
			} else {
				log.Warnf("不支持的 %s, 仅支持ipv4-A、ipv6-AAAA, ", dnsType)
				continue
			}

			responseBody, err = io.ReadAll(resp.Body)
			if err != nil {
				log.Errorf("解析响应体错误: %+v", err)
				resp.Body.Close()
				continue
			}
			resp.Body.Close()

			// 获取本地IP
			localIP := string(responseBody)
			localIPContent := fmt.Sprintf("域名 %s.%s 的 IP 应为 %s\n", name, domain, localIP)

			resp, err := retryRequest("GET", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", domain), nil, header)
			if err != nil {
				log.Errorf("获取根域名 %s 的 ZoneName 错误: %+v", domain, err)
				content += localIPContent
				return
			}

			responseBody, err = io.ReadAll(resp.Body)
			if err != nil {
				log.Errorf("解析响应体错误: %+v", err)
				content += localIPContent
				resp.Body.Close()
				continue
			}
			resp.Body.Close()

			var zoneInfos ZoneInfos
			err = json.Unmarshal(responseBody, &zoneInfos)
			if err != nil {
				log.Errorf("解析 ZoneInfos 错误: %+v", err)
				content += localIPContent
				continue
			}
			if len(zoneInfos.Result) == 0 {
				log.Warnf("未找到域名 %s 的 ZoneName", domain)
				content += localIPContent
				continue
			}
			zid := zoneInfos.Result[0].ID
			if zid == "" {
				log.Warnf("未找到域名 %s 的 ZoneID", domain)
				content += localIPContent
				continue
			}

			resp, err = retryRequest("GET", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s.%s", zid, name, domain), nil, header)
			if err != nil {
				log.Warnf("获取域名 %s.%s 的 DNS 记录错误: %s", name, domain, err)
				content += localIPContent
				continue
			}
			responseBody, err = io.ReadAll(resp.Body)
			if err != nil {
				log.Errorf("解析响应体错误: %+v", err)
				content += localIPContent
				resp.Body.Close()
				continue
			}
			resp.Body.Close()

			var dnsInfos DNSInfos
			err = json.Unmarshal(responseBody, &dnsInfos)
			if err != nil {
				log.Errorf("解析 DNS 记录错误: %+v", err)
				content += localIPContent
				continue
			}
			rid := ""
			remortIP := ""
			proxied := false
			for _, record := range dnsInfos.Result {
				if record.Type == dnsType {
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
					"type":    dnsType,
					"name":    fmt.Sprintf("%s.%s", name, domain),
					"content": localIP,
					"proxied": proxied,
				}

				resp, err = retryRequest("PUT", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zid, rid), params, header)
				if err != nil {
					log.Errorf("域名 %s.%s 更新错误: %+v", name, domain, err)
					continue
				}
				if resp.StatusCode == 200 {
					log.Infof("成功更新 %s.%s 的IP 为 %s", name, domain, localIP)
					resp.Body.Close()
				} else {
					log.Warnf("%s.%s的ip更新失败", name, domain)
					resp.Body.Close()
				}
			} else {
				log.Infof("域名 %s.%s 的IP为 %s 未改变, 无需更新", name, domain, localIP)
				resp.Body.Close()
				continue
			}
		}
	}
}

func main() {
	// 定义命令行参数
	filePath := flag.String("file", "config.json", "文件路径和名称")

	// 解析命令行参数
	flag.Parse()

	// 设置日志输出
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	// 打开文件
	file, err := os.Open(*filePath)
	if err != nil {
		log.Errorf("无法打开配置文件: %+v", err)
		return
	}
	defer file.Close()

	// 读取文件内容
	bytes, err := io.ReadAll(file)
	if err != nil {
		log.Errorf("无法读取配置文件: %+v", err)
		return
	}

	// 解析 JSON 文件内容
	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Errorf("无法解析配置文件: %+v", err)
		return
	}
	if config.Key == "" || config.Email == "" {
		log.Errorf("Key 或 Email 不能为空")
		return
	}
	handleMain(config)
}
