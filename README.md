# updateCFIP

# 使用方法

### 配置config.json

{"email": "账户email", "key": "账户key", "domainInfos":[["名称", "根域", "A,AAAA"]]}

比如完整域名为 A.B.com，根域为 B.com, 同时更新IPV4与IPV6 则config.json 为 

{"email": "账户email", "key": "账户key", "domainInfos":[["A", "B.com", "A,AAAA"]]},

### 运行程序

./updateCFIP -file config.json文件所在位置

若config.json与程序同目录，可直接 ./updateCFIP 运行程序
