package serviceCache

import (
	// 标准库
	"reflect"
	"time"

	// 第三方库
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

type CacheParams struct {
	MaxCacheLimit int
	Cate          string
}

// serviceCache 服务缓存
var serviceCache = cache.New(4*time.Hour, 10*time.Minute)

func Get(key string) (interface{}, bool) {
	return serviceCache.Get(key)
}

func Set(key string, value interface{}, duration time.Duration, cacheParams ...CacheParams) {
	if len(cacheParams) > 0 {
		// 删除最早的缓存条目
		oldestKey, oldestTime, needDele := getOldestKey(serviceCache, cacheParams[0])
		if needDele {
			formattedTime := oldestTime.Format("2006-01-02 15:04:05")
			logrus.Debugf("setCache 函数删除最早的缓存条目: %s, 过期时间: %v.", oldestKey, formattedTime)
			serviceCache.Delete(oldestKey)
		}
	}

	serviceCache.Set(key, value, duration)
}

func Delete(key string) {
	serviceCache.Delete(key)
}

func getOldestKey(serviceCache *cache.Cache, cacheParams CacheParams) (oldestKey string, oldestTime time.Time, needDelete bool) {
	count := 0
	for key, value := range serviceCache.Items() {
		if cacheParams.MaxCacheLimit > 0 && cacheParams.Cate != "" {
			cate := reflect.TypeOf(value.Object).String()
			if cate == cacheParams.Cate {
				// 将 value.Expiration (int64) 转换为 time.Time
				expirationTime := time.Unix(0, value.Expiration)
				// 比较并找到最早的过期时间
				if oldestTime.IsZero() || expirationTime.Before(oldestTime) {
					oldestKey = key
					oldestTime = expirationTime
				}
				count++
			}
		}
	}
	if count >= cacheParams.MaxCacheLimit {
		needDelete = true
	}
	return oldestKey, oldestTime, needDelete
}
