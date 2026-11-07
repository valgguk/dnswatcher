package collector

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

var RootServers = []string{
	"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
	"192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
	"192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
	"202.12.27.33",
}

type TLDCollector struct{ client *dns.Client }

func NewTLDCollector(client *dns.Client) *TLDCollector {
	if client == nil {
		client = new(dns.Client)
	}
	return &TLDCollector{client: client}
}

func ExtractTLD(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	parts := strings.Split(domain, ".")
	if len(parts) < 2 || parts[len(parts)-1] == "" || parts[len(parts)-2] == "" {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}
	return parts[len(parts)-1], nil
}

func (c *TLDCollector) GetDelegatedNS(ctx context.Context, domain string) ([]string, error) {
	tld, err := ExtractTLD(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to extract TLD: %w", err)
	}
	tldServers, err := c.resolve(ctx, dns.Fqdn(tld), RootServers)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TLD servers: %w", err)
	}
	servers, err := c.resolve(ctx, dns.Fqdn(domain), tldServers)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve delegated NS: %w", err)
	}
	return servers, nil
}

func (c *TLDCollector) resolve(ctx context.Context, name string, servers []string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeNS)
	for _, server := range servers {
		addresses, err := serverAddresses(ctx, server)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			resp, _, err := c.client.ExchangeContext(ctx, msg, net.JoinHostPort(address, "53"))
			if err != nil || resp == nil {
				continue
			}
			names := extractNS(append(resp.Answer, resp.Ns...))
			if len(names) > 0 {
				return names, nil
			}
		}
	}
	return nil, fmt.Errorf("no NS found for %s", name)
}

func serverAddresses(ctx context.Context, server string) ([]string, error) {
	if net.ParseIP(server) != nil {
		return []string{server}, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", strings.TrimSuffix(server, "."))
	if err != nil {
		return nil, err
	}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, ip.String())
	}
	return addresses, nil
}

func extractNS(records []dns.RR) []string {
	names := make([]string, 0)
	seen := make(map[string]struct{})
	for _, record := range records {
		ns, ok := record.(*dns.NS)
		if !ok {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSpace(ns.Ns), ".")
		if name == "" {
			continue
		}
		if _, exists := seen[name]; !exists {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}
