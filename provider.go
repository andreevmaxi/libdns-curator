package libdnscurator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/libdns/libdns"
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
		p.APIBase = "https://api.qrator.net"
	}
}

// GetRecords (not implemented yet)
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return nil, fmt.Errorf("not implemented")
}

// AppendRecords -> используем certrequest_upload
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.ensureClient()
	p.ensureDefaults()

	if len(recs) < 2 {
		return nil, fmt.Errorf("need at least 2 records: cert + key")
	}

	certPEM := recs[0].Value
	keyPEM := recs[1].Value

	req := map[string]interface{}{
		"method": "certrequest_upload",
		"params": []string{certPEM, keyPEM},
		"id":     1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/request/client/1", p.APIBase), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Qrator-Auth", p.APIToken)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("qrator API error: %s", string(b))
	}

	// Вернём recs, т.к. они "добавлены"
	return recs, nil
}

// SetRecords (not implemented yet)
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, fmt.Errorf("not implemented")
}

// DeleteRecords -> certificate_remove
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.ensureClient()
	p.ensureDefaults()

	var deleted []libdns.Record

	for _, rec := range recs {
		if rec.Value == "" {
			return nil, fmt.Errorf("record Value required (certificate ID)")
		}

		payload := map[string]interface{}{
			"method": "certificate_remove",
			"params": []interface{}{rec.Value},
			"id":     1,
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.APIBase+"/request/client/1", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Qrator-Auth", p.APIToken)

		resp, err := p.client.Do(req)
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

