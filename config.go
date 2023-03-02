package main

type UpstreamDnsConfig struct {
	Server string `json:"server"`
	Port   string `json:"port"`
}
type Config struct {
	LogLevel    string            `json:"log-level" default:"INFO"`
	Server      string            `json:"server"`
	Subnet      string            `json:"subnet"`
	UpstreamDns UpstreamDnsConfig `json:"upstream-dns"`
}
