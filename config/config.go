package config

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	// 本地库
	"updateCFIP/checkFile"

	log "github.com/sirupsen/logrus"
)

type Sub struct {
	Name  string   `json:"name"`  // 域名
	Cates []string `json:"cates"` // 记录类型
}

type Tele struct {
	Update bool   `json:"update"` // 是否启用Telegram通知
	Url    string `json:"url"`    // Telegram Bot API地址
	ID     string `json:"id"`     // Telegram聊天ID
}

type API struct {
	IPv4 string `json:"ipv4"` // 获取DNS记录的API
	IPv6 string `json:"ipv6"` // 获取DNS记录的API
}

type Config struct {
	Debug     bool     `json:"debug"`     // 调试模式
	APIs      API      `json:"api"`       // API地址
	Key       string   `json:"key"`       // 密钥
	Email     string   `json:"email"`     // 邮箱
	Domain    string   `json:"domain"`    // 域名
	PreferIPV string   `json:"preferIPV"` // 偏好IPV模式
	Dns       []string `json:"dns"`       // DNS配置
	Subs      []Sub    `json:"subs"`      // 域名列表
	Tele      Tele     `json:"telegram"`  // Telegram配置
}

var GlobalConfig *Config

func init() {
	GlobalConfig = &Config{}
}

// 加载配置文件
func LoadConfig(configPath string) error {
	// 检查文件是否存在
	configPath, err := checkFile.CheckFileExists(configPath)
	if err != nil {
		return err
	}

	// 如果文件存在，正常加载配置
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.Errorf("关闭文件错误: %+v", err)
		}
	}()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		return err
	}

	GlobalConfig = &config

	return nil
}

// 提取偏好IPV模式
func GetPreferIPV() string {
	switch {
	case strings.Contains(GlobalConfig.PreferIPV, "4"):
		GlobalConfig.PreferIPV = "ipv4"
	case strings.Contains(GlobalConfig.PreferIPV, "6"):
		GlobalConfig.PreferIPV = "ipv6"
	default:
		GlobalConfig.PreferIPV = "auto"
	}
	return GlobalConfig.PreferIPV
}

// 提取DNS值
func GetDns(preferIPV string) (dns, port string) {
	// 遍历DNS列表，返回第一个符合偏好IPV模式的DNS
	for _, dns := range GlobalConfig.Dns {
		dns, port = removePort(dns)
		parsedIP := net.ParseIP(dns)
		if parsedIP != nil {
			if parsedIP.To4() == nil {
				if !strings.HasPrefix(dns, "[") {
					dns = "[" + dns
				}
				if !strings.HasSuffix(dns, "]") {
					dns += "]"
				}
				if preferIPV == "ipv6" || preferIPV == "auto" {
					log.Debugf("client 使用指定的 DNS: %s", dns)
					return dns, port
				}
			} else {
				if preferIPV == "ipv4" || preferIPV == "auto" {
					log.Debugf("client 使用指定的 DNS: %s", dns)
					return dns, port
				}
			}
		} else {
			// 如果不是IP地址，直接返回
			log.Warnf("GetDns 函数检测到非IP地址的DNS: %s", dns)
			return dns, port
		}
	}
	return "", ""
}

// 提取调试模式
func GetDebug() bool {
	return GlobalConfig.Debug
}

// 提取API地址
func GetAPI() API {
	return GlobalConfig.APIs
}

// 提取密钥
func GetKey() string {
	return GlobalConfig.Key
}

// 提取邮箱
func GetEmail() string {
	return GlobalConfig.Email
}

// 提取主域名
func GetDomain() string {
	return GlobalConfig.Domain
}

// 提取Telegram配置
func GetTele() Tele {
	return GlobalConfig.Tele
}

// 提取域名列表
func GetSubs() []Sub {
	return GlobalConfig.Subs
}

func removePort(addr string) (ip, port string) {
	// 处理 [IPv6]:端口
	re := regexp.MustCompile(`^\[([a-fA-F0-9:]+)\](:\d+)?$`)
	matches := re.FindStringSubmatch(addr)
	if len(matches) == 3 {
		ip = matches[1]
		if matches[2] != "" {
			port = matches[2][1:] // 去掉冒号
		}
		return ip, port
	}
	// 处理 IPv4:端口 或 域名:端口
	if idx := strings.LastIndex(addr, ":"); idx != -1 && strings.Count(addr, ":") == 1 {
		ip = addr[:idx]
		port = addr[idx+1:]
		return ip, port
	}
	return addr, ""
}
