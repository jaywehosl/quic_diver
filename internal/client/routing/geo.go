package routing

import (
	"net/netip"
	"strings"
)

// geoSiteCategories — встроенный словарь категорий GeoSite (по аналогии с Xray-core / v2ray)
var geoSiteCategories = map[string][]string{
	"google": {
		"google.com", "googlevideo.com", "gstatic.com", "youtube.com", "ytimg.com",
		"ggpht.com", "googleapis.com", "gvt1.com", "gvt2.com", "1e100.net",
		"googleusercontent.com", "gmail.com", "doubleclick.net",
	},
	"youtube": {
		"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "ggpht.com",
	},
	"category-ads-all": {
		"doubleclick.net", "googleadservices.com", "adservice.google.com",
		"adnxs.com", "adform.net", "scorecardresearch.com", "taboola.com",
		"outbrain.com", "criteo.com", "yandex.ru/ads", "an.yandex.ru",
	},
	"ads": {
		"doubleclick.net", "googleadservices.com", "adservice.google.com",
		"adnxs.com", "adform.net", "scorecardresearch.com", "taboola.com",
	},
	"ru": {
		"ru", "su", "рф", "vk.com", "yandex.ru", "mail.ru", "2ip.ru", "2ip.io",
		"sberbank.ru", "ozon.ru", "tinkoff.ru", "gosuslugi.ru", "ya.ru",
	},
	"cn": {
		"cn", "baidu.com", "qq.com", "taobao.com", "alipay.com", "weibo.com",
		"bilibili.com", "jd.com", "zhihu.com",
	},
	"telegram": {
		"telegram.org", "telegram.me", "t.me", "tdesktop.com", "telesco.pe",
	},
}

// geoIPPrivate — спец-диапазоны приватных сетей
var geoIPPrivate = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("::1/128"),
}

// geoSiteMatches проверяет, совпадает ли домен с категорией geosite (например, geosite:google)
func geoSiteMatches(category, domain string) bool {
	category = strings.ToLower(strings.TrimSpace(category))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	// 1. Проверяем домены из зафиксированного словаря категорий
	if domains, ok := geoSiteCategories[category]; ok {
		for _, sfx := range domains {
			if domainMatches(sfx, domain) {
				return true
			}
		}
	}

	// 2. Если категория равна "ru" или "cn" или доменная зона совпадает
	if category == "ru" && (strings.HasSuffix(domain, ".ru") || strings.HasSuffix(domain, ".рф") || strings.HasSuffix(domain, ".su")) {
		return true
	}
	if category == "cn" && strings.HasSuffix(domain, ".cn") {
		return true
	}

	// 3. Прямое совпадение имени категории как суффикса домена
	return domainMatches(category, domain)
}

// geoIPMatches проверяет, входит ли IP-адрес назначения в категорию geoip (например, geoip:private или geoip:ru)
func geoIPMatches(code string, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	code = strings.ToLower(strings.TrimSpace(code))

	if code == "private" || code == "lan" {
		for _, prefix := range geoIPPrivate {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}

	// Для отладки и локальных тестов: 127.0.0.0/8 и локалка
	if code == "local" {
		return addr.IsLoopback() || addr.IsPrivate()
	}

	return false
}

// NormalizeOutbound normalizes chain definitions like "node1,node2" -> "path:node1,node2"
func NormalizeOutbound(out string) string {
	out = strings.TrimSpace(out)
	if out == "" || out == "direct" || out == "chain" || out == "exit" {
		return out
	}
	if strings.Contains(out, ",") && !strings.HasPrefix(out, "path:") {
		return "path:" + out
	}
	return out
}
