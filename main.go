package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
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

func retryRequest(method, url string, body *bytes.Buffer, header map[string]string) (*http.Response, error) {
	maxRetries := 5               // 最大重试次数
	retryDelay := 2 * time.Second // 重试间隔时间

	var err error
	var req *http.Request
	var client http.Client
	var resp *http.Response

	for i := 0; i < maxRetries; i++ {
		if method == http.MethodGet {
			req, err = http.NewRequest(http.MethodGet, url, nil)
		} else if method == http.MethodPut {
			req, err = http.NewRequest(http.MethodPut, url, body)
		} else if method == http.MethodPost {
			req, err = http.NewRequest(http.MethodPost, url, body)
		} else {
			return nil, fmt.Errorf("不支持的method: %s", method)
		}

		if err != nil {
			log.Infof("错误: %+v", err)
			return nil, fmt.Errorf("错误: %+v", err)
		}

		for key, value := range header {
			req.Header.Set(key, value)
		}

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}

		// 请求失败，等待重试
		log.Warnf("请求 %s 失败, 等待 %ds 后重试: %+v", url, retryDelay/1000000000, err)
		time.Sleep(retryDelay)
		resp.Body.Close()
	}
	return nil, fmt.Errorf("访问 %s 失败: %+v", url, err)
}

func handleMain(config Config) {
	content := ""

	// 设置请求头
	header := map[string]string{
		"X-Auth-Key": config.Key,
		"X-Auth-Email": config.Email,
		"Accept": "application/json",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36",
	}

	defer func() {
		content = strings.TrimSpace(content)
		if config.Telegram.Update && content != "" {
			// 更新IP到指定URL
			params := map[string]string{
				"chat_id": config.Telegram.ID,
				"text":    content,
			}
			body, err := json.Marshal(params)
			if err != nil {
				log.Infof("错误: %+v", err)
				return
			}
			_, err = retryRequest("POST", config.Telegram.Url, bytes.NewBuffer(body), header)
			if err != nil {
				log.Infof("获取IPV6错误: %+v", err)
				return
			}
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

			var result map[string]interface{}
			json.Unmarshal(responseBody, &result)
			zid := result["result"].([]interface{})[0].(map[string]interface{})["id"].(string)
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

			var dnsRecords map[string]interface{}
			json.Unmarshal(responseBody, &dnsRecords)
			resultList := dnsRecords["result"].([]interface{})
			rid := ""
			remortIP := ""
			proxied := false
			for _, record := range resultList {
				if record.(map[string]interface{})["type"].(string) == dnsType {
					rid = record.(map[string]interface{})["id"].(string)
					remortIP = record.(map[string]interface{})["content"].(string)
					proxied = record.(map[string]interface{})["proxied"].(bool)
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
				body, err := json.Marshal(params)
				if err != nil {
					log.Errorf("Json 格式化错误: %+v", err)
					continue
				}

				resp, err = retryRequest("PUT", fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zid, rid), bytes.NewBuffer(body), header)
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
