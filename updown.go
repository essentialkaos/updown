package updown

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2025 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/essentialkaos/ek/v13/req"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const (
	EVENT_DOWN             = "check.down"
	EVENT_UP               = "check.up"
	EVENT_SSL_INVALID      = "check.ssl_invalid"
	EVENT_SSL_VALID        = "check.ssl_valid"
	EVENT_SSL_EXPIRTAION   = "check.ssl_expiration"
	EVENT_SSL_RENEWED      = "check.ssl_renewed"
	EVENT_PERFORMANCE_DROP = "check.performance_drop"
)

// ////////////////////////////////////////////////////////////////////////////////// //

// Date is JSON date
type Date struct {
	time.Time
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Event contains basic event data
type Event struct {
	Type        string `json:"event"`
	Time        Date   `json:"time"`
	Description string `json:"description"`
	Check       *Check `json:"check"`
}

// EventDown sent when a check goes down (after confirmation)
//
// https://updown.io/api#check.down
type EventDown struct {
	Event
	Downtime *Downtime `json:"downtime"`
}

// EventUp sent when a check is back up (recovery following a check.down event)
//
// https://updown.io/api#check.up
type EventUp struct {
	Event
	Downtime *Downtime `json:"downtime"`
}

// EventSSLInvalid sent when the SSL certificate is considered invalid
//
// https://updown.io/api#check.ssl_invalid
type EventSSLInvalid struct {
	Event
	SSL *SSL `json:"ssl"`
}

// EventSSLValid sent when SSL certificate is valid again (recovery after
// a check.ssl_invalid event)
//
// https://updown.io/api#check.ssl_valid
type EventSSLValid struct {
	Event
	SSL *SSL `json:"ssl"`
}

// EventSSLExpiration sent when your SSL certificate approaches expiration
// date (1, 7, 14, and 30 days before for 1y certs)
//
// https://updown.io/api#check.ssl_expiration
type EventSSLExpiration struct {
	Event
	SSL *SSL `json:"ssl"`
}

// EventSSLRenewed sent when the SSL certificate was renewed close to
// expiration (recovery for check.ssl_expiration)
//
// https://updown.io/api#check.ssl_renewed
type EventSSLRenewed struct {
	Event
	SSL *SSLRenew `json:"ssl"`
}

// EventPerformanceDrop sent when the Apdex drops more than 30% below the lowest
// of the last 5 hours
//
// https://updown.io/api#check.performance_drop
type EventPerformanceDrop struct {
	Event
	ApdexDropped string              `json:"apdex_dropped"`
	LastMetrics  *PerformanceMetrics `json:"last_metrics"`
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Webhook contains webhook payload
type Webhook []*WebhookEvent

// WebhookEvent contains webhook event data
type WebhookEvent struct {
	Type  string
	Event any
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Check contains check info
type Check struct {
	Token             string            `json:"token"`
	URL               string            `json:"url"`
	Alias             string            `json:"alias"`
	LastStatus        int               `json:"last_status"`
	Uptime            float64           `json:"uptime"`
	IsDown            bool              `json:"down"`
	DownSince         Date              `json:"down_since"`
	UpSince           Date              `json:"up_since"`
	Error             string            `json:"error"`
	Period            int               `json:"period"`
	Apdex             float64           `json:"apdex_t"`
	StringMatch       string            `json:"string_match"`
	IsEnabled         bool              `json:"enabled"`
	IsPublished       bool              `json:"published"`
	LastCheckAt       Date              `json:"last_check_at"`
	NextCheckAt       Date              `json:"next_check_at"`
	CreatedAt         Date              `json:"created_at"`
	MuteUntil         Date              `json:"mute_until"`
	FaviconURL        string            `json:"favicon_url"`
	HTTPVerb          string            `json:"http_verb"`
	HTTPBody          string            `json:"http_body"`
	Recipients        []string          `json:"recipients"`
	DisabledLocations []string          `json:"disabled_locations"`
	CustomHeaders     map[string]string `json:"custom_headers"`
	SSL               *SSLStatus        `json:"ssl,omitempty"`
	Metrics           *Metrics          `json:"metrics,omitempty"`
}

// Checks is a slice with checks
type Checks []*Check

// SSLStatus contains info about SSL certificate status
type SSLStatus struct {
	TestedAt  Date   `json:"tested_at"`
	ExpiresAt Date   `json:"expires_at"`
	IsValid   bool   `json:"valid"`
	Error     string `json:"error"`
}

// Downtime contains info about downtime
type Downtime struct {
	ID          string           `json:"id"`
	DetailsURL  string           `json:"details_url"`
	Error       string           `json:"error"`
	StartedAt   Date             `json:"started_at"`
	EndedAt     Date             `json:"ended_at"`
	Duration    int              `json:"duration"`
	IsPartial   bool             `json:"partial"`
	DownResults []*DowntimeCheck `json:"down_results"`
	UpResults   []*DowntimeCheck `json:"up_results"`
}

type DowntimeCheck struct {
	ID         string            `json:"id"`
	Status     string            `json:"status"`
	DetailsURL string            `json:"details_url"`
	Request    *DowntimeRequest  `json:"request"`
	Response   *DowntimeResponse `json:"response"`
}

// DowntimeRequest contains info with downtime check request
type DowntimeRequest struct {
	SentAt      Date              `json:"sent_at"`
	HTTPMethod  string            `json:"http_method"`
	HTTPVersion string            `json:"http_version"`
	SentHeaders map[string]string `json:"sent_headers"`
	Node        string            `json:"node"`
}

// DowntimeResponse contains info with downtime check response
type DowntimeResponse struct {
	ReceivedAt      Date              `json:"received_at"`
	FinalURL        string            `json:"final_url"`
	Code            int               `json:"code"`
	IP              string            `json:"ip"`
	ReceivedHeaders map[string]string `json:"received_headers"`
}

// DowntimeTimings contains downtime check timings
type DowntimeTimings struct {
	NameLookup float64 `json:"namelookup"`
	Connection float64 `json:"connection"`
	Handshake  float64 `json:"handshake"`
	Response   float64 `json:"response"`
	Total      float64 `json:"total"`
}

// DowntimeIPv4Check contains info about check through IPv4 network
type DowntimeIPv4Check struct {
	Status          string            `json:"status"`
	IP              string            `json:"ip"`
	Code            int               `json:"code"`
	Timings         *DowntimeTimings  `json:"timings"`
	ReceivedHeaders map[string]string `json:"received_headers"`
}

// DowntimeIPv6Check contains info about check through IPv6 network
type DowntimeIPv6Check struct {
	Status  string           `json:"status"`
	IP      string           `json:"ip"`
	Code    int              `json:"code"`
	Timings *DowntimeTimings `json:"timings"`
}

// Downtimes is slice with downtimes
type Downtimes []*Downtime

// Metrics is apdex metrics
type Metrics struct {
	Uptime   float64       `json:"uptime"`
	Apdex    float64       `json:"apdex"`
	Timings  *TimingStats  `json:"timings"`
	Requests *RequestStats `json:"requests"`
}

// Timings check timings info
type TimingStats struct {
	Redirect   int `json:"redirect"`
	NameLookup int `json:"namelookup"`
	Connection int `json:"connection"`
	Handshake  int `json:"handshake"`
	Response   int `json:"response"`
	Total      int `json:"total"`
}

// RequestStats contains check requests statistics
type RequestStats struct {
	Samples        int                `json:"samples"`
	Failures       int                `json:"failures"`
	Satisfied      int                `json:"satisfied"`
	Tolerated      int                `json:"tolerated"`
	ByResponseTime *ResponseTimeStats `json:"by_response_time"`
}

// ResponseTimeStats contains check response time statistics
type ResponseTimeStats struct {
	Under125 int `json:"under125"`
	Under250 int `json:"under250"`
	Under500 int `json:"under500"`
	Under1k  int `json:"under1000"`
	Under2k  int `json:"under2000"`
	Under4k  int `json:"under4000"`
	Under8k  int `json:"under8000"`
	Under16k int `json:"under16000"`
	Under32k int `json:"under32000"`
}

// Node contains info about check node
type Node struct {
	IP          string  `json:"ip"`
	IPv6        string  `json:"ip6"`
	City        string  `json:"city"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lng"`
}

// Nodes is a map of check nodes
type Nodes map[string]*Node

// SSL contains info about SSL certificate and it's status
type SSL struct {
	Cert                 *Cert  `json:"cert"`
	Error                string `json:"error"`
	DaysBeforeExpiration int    `json:"days_before_expiration"`
}

// SSLRenew contains info about renewed certificate
type SSLRenew struct {
	NewCert *Cert `json:"new_cert"`
	OldCert *Cert `json:"old_cert"`
}

// Cert contains SSL certificate info
type Cert struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	From      Date   `json:"from"`
	To        Date   `json:"to"`
	Algorithm string `json:"algorithm"`
}

// Recipient contains info about alert recipient
type Recipient struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Recipients is a slice with recipients
type Recipients []*Recipient

// StatusPage contains info about status check
type StatusPage struct {
	Token       string   `json:"token"`
	URL         string   `json:"url"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Visibility  string   `json:"visibility"`
	AccessKey   string   `json:"access_key"`
	Checks      []string `json:"checks"`
}

// StatusPages is a slice with status pages
type StatusPages []*StatusPage

// PerformanceMetrics is performance drop metrics
type PerformanceMetrics struct {
	Metrics []*PerformanceApdex
}

// PerformanceApdex contains apdex metric
type PerformanceApdex struct {
	Date  time.Time
	Apdex float64
}

// ////////////////////////////////////////////////////////////////////////////////// //

// MetricsOptions is options for metrics request
type MetricsOptions struct {
	From    time.Time
	To      time.Time
	GroupBy string
}

// ////////////////////////////////////////////////////////////////////////////////// //

// basicEvent is basic event type
type basicEvent struct {
	Type string `json:"event"`
}

// apdexMap is map with apdex info for specific date
type apdexMap map[string]*apdexInfo

// apdexInfo contains basic apdex info
type apdexInfo struct {
	Apdex float64 `json:"apdex"`
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Client is Updown API client
type Client struct {
	engine *req.Engine
	apiKey string
	calls  uint
}

// ////////////////////////////////////////////////////////////////////////////////// //

var (
	ErrEmptyAPIKey = errors.New("API key is empty")
	ErrNilClient   = errors.New("Client is nil")
	ErrEmptyToken  = errors.New("Token is empty")
)

// ////////////////////////////////////////////////////////////////////////////////// //

// apiURL is URL of updown.io public API
var apiURL = "https://updown.io/api"

// defaultHeaders is a collection of default request headers
var defaultHeaders = req.Headers{"Accept-Encoding": "gzip"}

// ////////////////////////////////////////////////////////////////////////////////// //

// ParseWebhook parses webhook data
func ParseWebhook(data []byte) (Webhook, error) {
	types := []*basicEvent{}
	err := json.Unmarshal(data, &types)

	if err != nil {
		return nil, err
	}

	events := []any{}

	for _, ev := range types {
		switch ev.Type {
		case EVENT_DOWN:
			events = append(events, &EventDown{})
		case EVENT_UP:
			events = append(events, &EventUp{})
		case EVENT_SSL_INVALID:
			events = append(events, &EventSSLInvalid{})
		case EVENT_SSL_VALID:
			events = append(events, &EventSSLValid{})
		case EVENT_SSL_RENEWED:
			events = append(events, &EventSSLRenewed{})
		case EVENT_SSL_EXPIRTAION:
			events = append(events, &EventSSLExpiration{})
		case EVENT_PERFORMANCE_DROP:
			events = append(events, &EventPerformanceDrop{})
		default:
			events = append(events, nil)
		}
	}

	json.Unmarshal(data, &events)

	var result Webhook

	// Append to result only known event types
	for i, ev := range types {
		switch ev.Type {
		case EVENT_DOWN, EVENT_UP, EVENT_SSL_INVALID, EVENT_SSL_VALID, EVENT_SSL_RENEWED,
			EVENT_SSL_EXPIRTAION, EVENT_PERFORMANCE_DROP:
			result = append(result, &WebhookEvent{Type: ev.Type, Event: events[i]})
		}
	}

	return result, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// NewClient creates new client instance
func NewClient(apiKey string) (*Client, error) {
	if apiKey == "" {
		return nil, ErrEmptyAPIKey
	}

	c := &Client{engine: &req.Engine{}, apiKey: apiKey}
	c.SetUserAgent("", "")

	return c, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Calls returns total number of API calls made by the client
func (c *Client) Calls() uint {
	if c == nil {
		return 0
	}

	return c.calls
}

// SetUserAgent sets client user agent
func (c *Client) SetUserAgent(app, version string) {
	if c == nil || c.engine == nil {
		return
	}

	if app == "" || version == "" {
		c.engine.SetUserAgent("EK|Updown.go", "1")
	} else {
		c.engine.SetUserAgent(app, version, "EK|Updown.go/1")
	}
}

// ////////////////////////////////////////////////////////////////////////////////// //

// GetChecks returns info about all checks
//
// https://updown.io/api#GET-/api/checks
func (c *Client) GetChecks() (Checks, error) {
	if c == nil || c.engine == nil {
		return nil, ErrNilClient
	}

	result := Checks{}
	err := c.sendRequest(req.GET, "/checks", &result, nil, nil)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetCheck returns info about check with given token
//
// https://updown.io/api#GET-/api/checks/:token
func (c *Client) GetCheck(token string, withMetrics bool) (*Check, error) {
	switch {
	case c == nil || c.engine == nil:
		return nil, ErrNilClient
	case token == "":
		return nil, ErrEmptyToken
	}

	var query req.Query

	if withMetrics {
		query = req.Query{"metrics": true}
	}

	result := &Check{}
	err := c.sendRequest(req.GET, "/checks/"+token, &result, nil, query)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetDowntimes returns all the downtimes of a check
//
// https://updown.io/api#GET-/api/checks/:token/downtimes
func (c *Client) GetDowntimes(token string, detailed bool) (Downtimes, error) {
	switch {
	case c == nil || c.engine == nil:
		return nil, ErrNilClient
	case token == "":
		return nil, ErrEmptyToken
	}

	var result Downtimes

	query := req.Query{}

	if detailed {
		query["results"] = true
	}

	for page := 1; page < 100; page++ {
		query["page"] = page
		downtimes := Downtimes{}
		err := c.sendRequest(
			req.GET, "/checks/"+token+"/downtimes",
			&downtimes, nil, query,
		)

		if err != nil {
			return nil, err
		}

		result = append(result, downtimes...)

		if len(downtimes) != 100 {
			break
		}
	}

	return result, nil
}

// GetMetrics returns detailed metrics about the check
//
// https://updown.io/api#GET-/api/checks/:token/metrics
func (c *Client) GetMetrics(token string, options MetricsOptions) (*Metrics, error) {
	switch {
	case c == nil || c.engine == nil:
		return nil, ErrNilClient
	case token == "":
		return nil, ErrEmptyToken
	}

	query := options.toQuery()
	result := &Metrics{}

	err := c.sendRequest(req.GET, "/checks/"+token+"/metrics", &result, nil, query)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetNodes return list of all updown.io servers (monitoring & webhooks)
//
// https://updown.io/api#GET-/api/nodes
func (c *Client) GetNodes() (Nodes, error) {
	if c == nil || c.engine == nil {
		return nil, ErrNilClient
	}

	result := Nodes{}
	err := c.sendRequest(req.GET, "/nodes", &result, nil, nil)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetNodesIPs returns list all updown.io servers addresses
//
// https://updown.io/api#GET-/api/nodes/ips
func (c *Client) GetNodesIPs() ([]string, error) {
	if c == nil || c.engine == nil {
		return nil, ErrNilClient
	}

	result := []string{}
	err := c.sendRequest(req.GET, "/nodes/ips", &result, nil, nil)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetNodesIPsV4 returns list all updown.io servers IPv4 addresses
//
// https://updown.io/api#GET-/api/nodes/ipv4
func (c *Client) GetNodesIPsV4() ([]string, error) {
	if c == nil || c.engine == nil {
		return nil, ErrNilClient
	}

	result := []string{}
	err := c.sendRequest(req.GET, "/nodes/ipv4", &result, nil, nil)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetNodesIPsV6 returns list all updown.io servers IPv6 addresses
//
// https://updown.io/api#GET-/api/nodes/ipv6
func (c *Client) GetNodesIPsV6() ([]string, error) {
	if c == nil || c.engine == nil {
		return nil, ErrNilClient
	}

	result := []string{}
	err := c.sendRequest(req.GET, "/nodes/ipv6", &result, nil, nil)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetRecipients returns list all the possible alert recipients/channels on your account
//
// https://updown.io/api#GET-/api/recipients
func (c *Client) GetRecipients() (Recipients, error) {
	if c == nil || c.engine == nil {
		return nil, ErrNilClient
	}

	result := Recipients{}
	err := c.sendRequest(req.GET, "/recipients", &result, nil, nil)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetStatusPages returns list all your status pages
//
// https://updown.io/api#GET-/api/status-pages
func (c *Client) GetStatusPages() (StatusPages, error) {
	if c == nil || c.engine == nil {
		return nil, ErrNilClient
	}

	result := StatusPages{}
	err := c.sendRequest(req.GET, "/status-pages", &result, nil, nil)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// UnmarshalJSON parses JSON date
func (d *Date) UnmarshalJSON(b []byte) error {
	data := string(b)

	if data == "null" {
		d.Time = time.Time{}
		return nil
	}

	date, err := time.Parse(`"2006-01-02T15:04:05Z"`, data)

	if err != nil {
		return err
	}

	d.Time = date

	return nil
}

// UnmarshalJSON parses performance metrics
func (d *PerformanceMetrics) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}

	metrics := apdexMap{}
	err := json.Unmarshal(b, &metrics)

	if err != nil {
		return err
	}

	for k, v := range metrics {
		dt, err := time.Parse("2006-01-02T15:04:05Z", k)

		if err != nil {
			return err
		}

		d.Metrics = append(d.Metrics, &PerformanceApdex{Date: dt, Apdex: v.Apdex})
	}

	sort.Slice(d.Metrics, func(i, j int) bool {
		return d.Metrics[i].Date.Before(d.Metrics[j].Date)
	})

	return nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// toQuery converts options into request query
func (o MetricsOptions) toQuery() req.Query {
	if o.From.IsZero() && o.To.IsZero() && o.GroupBy == "" {
		return nil
	}

	query := req.Query{}

	if o.GroupBy != "" {
		query["group"] = o.GroupBy
	}

	if !o.From.IsZero() {
		query["from"] = o.From.Format("2006-01-02T15:04:05-07:00") // ISO8601
	}

	if !o.From.IsZero() {
		query["to"] = o.To.Format("2006-01-02T15:04:05-07:00") // ISO8601
	}

	return query
}

// ////////////////////////////////////////////////////////////////////////////////// //

// sendRequest sends request to API
func (c *Client) sendRequest(method, endpoint string, response, payload any, query req.Query) error {
	c.calls++

	r := req.Request{
		Method:  method,
		URL:     apiURL + endpoint,
		Query:   query,
		Accept:  req.CONTENT_TYPE_JSON,
		Headers: defaultHeaders,
		Auth:    req.AuthAPIKey{c.apiKey},
	}

	resp, err := c.engine.Do(r)

	if err != nil {
		return fmt.Errorf("Can't send request to API: %w", err)
	}

	if resp.StatusCode != req.STATUS_OK {
		return fmt.Errorf("API returned non-ok status code %d", resp.StatusCode)
	}

	if response != nil {
		err = resp.JSON(response)

		if err != nil {
			return fmt.Errorf("Can't decode API response: %w", err)
		}
	}

	return nil
}
