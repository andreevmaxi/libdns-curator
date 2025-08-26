// Package libdnstemplate implements a DNS record management client compatible
// with the libdns interfaces for <PROVIDER NAME>. TODO: This package is a
// template only. Customize all godocs for actual implementation.
package libdnscurator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"bytes"
	"io"
	"strings"

	"github.com/libdns/libdns"
	"github.com/caddyserver/certmagic"
)

type Provider struct {
	APIToken string `json:"api_token,omitempty"` 
	APIBase  string `json:"api_base,omitempty"`  
	
	client *http.Client
}

func (p *Provider) ensureClient() {
	if p.client == nil {
		p.client = &http.Client{Timeout: 10 * time.Second}
	}
}

func (p *Provider) ensureDefaults() {
	if p.APIBase == "" {
		p.APIBase = "https://api.qrator.net/"
	}
}

// структура для API-запросов
type dnsRecord struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return nil, fmt.Errorf("not implemented")
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, certPEM, keyPEM string) error {
	req := map[string]interface{}{
		"method": "certrequest_upload",
		"params": []string{
			certPEM,
			keyPEM,
		},
		"id": 1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/request/client/1", p.APIBase), bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Qrator-Auth", p.APIKey)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Result interface{} `json:"result"`
		Error  interface{} `json:"error"`
		ID     int         `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Error != nil {
		return fmt.Errorf("API error: %+v", result.Error)
	}

	return nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("not implemented")
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var deleted []libdns.Record

	for _, rec := range recs {
		// у нас rec.ID будет содержать ID сертификата (например, 302 из примера)
		if rec.ID == "" {
			return nil, fmt.Errorf("record ID required for deletion")
		}

		payload := map[string]interface{}{
			"method": "certificate_remove",
			"params": []interface{}{rec.ID},
			"id":     1,
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Provider.APIBase+"/request/client/1", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Qrator-Auth", p.Provider.APIToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("qrator API error: %s", string(b))
		}

		deleted = append(deleted, rec)
	}

	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
