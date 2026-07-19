// Package engine — fingerprint.go
//
// 原有内容已拆分重构为以下三个文件：
//
//   - probe.go    : ProbeResult 结构、NmapBinaryProbe（精准 Nmap 服务探测，无退化链）
//                   ActiveProbe（CDN/无特征防护主动试探与 HTTP 降级盲测）
//                   buildTags / resolveProtoURL / normalizeTag 辅助函数
//
//   - sniff.go    : SniffAndRoute（基础协议嗅探 + 流量分流）
//                   端口白名单 / TLS 握手探测 / TCP banner 检测
//
//   - webfp.go    : WebFingerprint（httpx 风格请求 + wappalyzergo DOM/头部深度解析）

package engine
