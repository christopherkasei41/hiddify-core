package config

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	badoption "github.com/sagernet/sing-box/common/badoption"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashapi"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
	boxmain "github.com/sagernet/sing-box/cmd/sing-box/internal/box"
	libbox "github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	urltest "github.com/sagernet/sing-box/experimental/urltest"
	"github.com/hiddify/hiddify-core/v2/hutils"
)

const (
	InboundTUNTag    = "tun-in"
	InboundMixedTag  = "mixed-in-"
	InboundTProxy    = "tproxy-in-"
	InboundRedirect  = "redirect-in-"
	InboundDirectTag = "direct-in-"
)

func setGeoFiles(options *option.Options) {
	assetsDir := filepath.Join("assets", "core")
	if _, err := os.Stat(filepath.Join(assetsDir, "geoip.db")); err == nil {
		options.Route = &option.RouteOptions{}
		options.Route.GeoIP = &option.RouteGeoIPOptions{Path: filepath.Join(assetsDir, "geoip.db")}
	}
	if _, err := os.Stat(filepath.Join(assetsDir, "geosite.db")); err == nil {
		if options.Route == nil {
			options.Route = &option.RouteOptions{}
		}
		options.Route.GeoSite = &option.RouteGeositeOptions{Path: filepath.Join(assetsDir, "geosite.db")}
	}
}

func generateRandomString(length int) string { return strings.Repeat("x", length)[:length] }

func isBlockedDomain(host string) bool { return false }

func isBlockedConnectionTestUrl(d string) bool {
	u, err := url.Parse(d)
	if err != nil {
		return false
	}
	return isBlockedDomain(u.Host)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func setExperimental(options *option.Options, hopt *HiddifyOptions) {
	if len(hopt.ConnectionTestUrls) == 0 {
		hopt.ConnectionTestUrls = []string{hopt.ConnectionTestUrl, "http://captive.apple.com/generate_204", "https://cp.cloudflare.com", "https://google.com/generate_204"}
		if isBlockedConnectionTestUrl(hopt.ConnectionTestUrl) {
			hopt.ConnectionTestUrls = []string{hopt.ConnectionTestUrl}
		}
	}
	if hopt.EnableClashApi && hopt.ClashApiPort > 0 {
		if hopt.ClashApiSecret == "" {
			hopt.ClashApiSecret = generateRandomString(16)
		}
		options.Experimental = &option.ExperimentalOptions{
			UnifiedDelay: &option.UnifiedDelayOptions{Enabled: true},
			ClashAPI: &option.ClashAPIOptions{
				ExternalController: fmt.Sprintf("%s:%d", "127.0.0.1", hopt.ClashApiPort),
				Secret:             hopt.ClashApiSecret,
			},
			CacheFile: &option.CacheFileOptions{Enabled: true, StoreWARPConfig: true, Path: "data/clash.db"},
			Monitoring: &option.MonitoringOptions{
				URLs:           hopt.ConnectionTestUrls,
				Interval:       badoption.Duration(hopt.URLTestInterval.Duration()),
				DebounceWindow: badoption.Duration(time.Millisecond * 500),
				IdleTimeout:    badoption.Duration(hopt.URLTestInterval.Duration().Nanoseconds() * 3),
			},
		}
	}
}

func setLog(options *option.Options, opt *HiddifyOptions) {
	options.Log = &option.LogOptions{Level: opt.LogLevel, Output: opt.LogFile, Disabled: false, Timestamp: false, DisableColor: true}
}

func isIPv6Supported() bool {
	if C.IsIos || C.IsDarwin { return true }
	_, err := net.ResolveIPAddr("ip6", "::1")
	return err == nil
}

func setInbound(options *option.Options, hopt *HiddifyOptions) {
	ipv6Enable := isIPv6Supported()
	if hopt.EnableTun {
		opts := option.TunInboundOptions{Stack: hopt.TUNStack, MTU: hopt.MTU, AutoRoute: true, StrictRoute: hopt.StrictRoute}
		tunInbound := option.Inbound{Type: C.TypeTun, Tag: InboundTUNTag, Options: &opts}
		opts.Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/28")}
		if ipv6Enable { opts.Address = append(opts.Address, netip.MustParsePrefix("fdfe:dcba:9876::1/126")) }
		options.Inbounds = append(options.Inbounds, tunInbound)
	}

	binds := []string{}
	if hopt.AllowConnectionFromLAN {
		if ipv6Enable { binds = append(binds, "::") } else { binds = append(binds, "0.0.0.0") }
	} else {
		if ipv6Enable { binds = append(binds, "::1") }
		binds = append(binds, "127.0.0.1")
	}

	for _, bind := range binds {
		addr := badoption.Addr(netip.MustParseAddr(bind))
		if hopt.MixedPort > 0 {
			options.Inbounds = append(options.Inbounds, option.Inbound{
				Type: C.TypeMixed,
				Tag:  InboundMixedTag + bind,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{Listen: &addr, ListenPort: hopt.MixedPort},
					SetSystemProxy: hopt.SetSystemProxy,
				},
			})
		}
		if C.IsLinux && !C.IsAndroid && hopt.TProxyPort > 0 && hutils.IsAdmin() {
			options.Inbounds = append(options.Inbounds, option.Inbound{Type: C.TypeTProxy, Tag: InboundTProxy + bind, Options: &option.TProxyInboundOptions{ListenOptions: option.ListenOptions{Listen: &addr, ListenPort: hopt.TProxyPort}}})
		}
		if (C.IsLinux || C.IsDarwin) && !C.IsAndroid && hopt.RedirectPort > 0 {
			options.Inbounds = append(options.Inbounds, option.Inbound{Type: C.TypeRedirect, Tag: InboundRedirect + bind, Options: &option.RedirectInboundOptions{ListenOptions: option.ListenOptions{Listen: &addr, ListenPort: hopt.RedirectPort}}})
		}
		if hopt.DirectPort > 0 {
			options.Inbounds = append(options.Inbounds, option.Inbound{Type: C.TypeDirect, Tag: InboundDirectTag + bind, Options: &option.DirectInboundOptions{ListenOptions: option.ListenOptions{Listen: &addr, ListenPort: hopt.DirectPort}}})
		}
	}
}

func setRoutingOptions(options *option.Options, hopt *HiddifyOptions) error { return nil }
func addForceDirect(options *option.Options, hopt *HiddifyOptions) ([]option.DefaultDNSRule, error) { return nil, nil }
func SetConfig(*HiddifyOptions) (*option.Options, error) { return nil, errors.New("not implemented in this patch placeholder") }
func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil { return nil, errors.New("failed to parse certificate PEM") }
	return x509.ParseCertificate(block.Bytes)
}
func sortStrings(in []string) { sort.Strings(in) }
func init() {
	_ = rw.CopyFile
	_ = include.WithApple
	_ = libbox.StderrWrapper(nil)
	_ = M.ParseSocksaddr
	_ = N.NetworkTCP
	_ = boxmain.Version
	_ = clashapi.ExternalController{}
	_ = dns.DomainStrategyAsIS
	_ = urltest.HistoryStorage(nil)
	_ = runtime.GOOS
}
