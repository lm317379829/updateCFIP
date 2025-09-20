package checkFile

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
)

func CheckFileExists(path string) (string, error) {
	path = filepath.Clean(path)
	fileInfo, err := os.Stat(path)
	logrus.Debugf("checkFileExists 函数检查文件: %+v.", fileInfo)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("文件 %s 不存在", path)
	}
	return path, nil
}
