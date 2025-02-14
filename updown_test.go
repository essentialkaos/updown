package updown

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2025 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"net/http"
	"testing"
	"time"

	. "github.com/essentialkaos/check"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const TEST_PORT = "56123"

// ////////////////////////////////////////////////////////////////////////////////// //

func Test(t *testing.T) { TestingT(t) }

type UpdownSuite struct{}

// ////////////////////////////////////////////////////////////////////////////////// //

var _ = Suite(&UpdownSuite{})

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *UpdownSuite) SetUpSuite(c *C) {
	apiURL = "http://127.0.0.1:" + TEST_PORT

	mux := http.NewServeMux()
	server := &http.Server{Addr: ":" + TEST_PORT, Handler: mux}

	mux.HandleFunc("GET /checks", checksHandler)
	mux.HandleFunc("GET /checks/ngg8", checkHandler)
	mux.HandleFunc("GET /checks/ngg8/downtimes", downtimesHandler)
	mux.HandleFunc("GET /checks/ngg8/metrics", metricsHandler)
	mux.HandleFunc("GET /nodes", nodesHandler)
	mux.HandleFunc("GET /nodes/ips", ipsHandler)
	mux.HandleFunc("GET /nodes/ipv4", ipV4Handler)
	mux.HandleFunc("GET /nodes/ipv6", ipV6Handler)
	mux.HandleFunc("GET /recipients", recipientsHandler)
	mux.HandleFunc("GET /status-pages", statusPagesHandler)

	go server.ListenAndServe()

	time.Sleep(time.Second)
}

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *UpdownSuite) TestDateParsing(c *C) {
	d := &Date{}

	err := d.UnmarshalJSON([]byte(`"2025-01-22T21:52:41Z"`))

	c.Assert(err, IsNil)
	c.Assert(d.Unix(), Equals, int64(1737582761))

	err = d.UnmarshalJSON([]byte(`null`))

	c.Assert(err, IsNil)
	c.Assert(d.IsZero(), Equals, true)

	err = d.UnmarshalJSON([]byte(`ABCD`))
	c.Assert(err, NotNil)
}

func (s *UpdownSuite) TestApdexParsing(c *C) {
	p := &PerformanceMetrics{}

	err := p.UnmarshalJSON([]byte(`null`))

	c.Assert(err, IsNil)

	err = p.UnmarshalJSON([]byte(`{
      "2023-03-12T02:00:00Z": { "apdex": 0.975 },
      "2023-03-12T03:00:00Z": { "apdex": 1 },
      "2023-03-12T04:00:00Z": { "apdex": 0.98 },
      "2023-03-12T05:00:00Z": { "apdex": 1 },
      "2023-03-12T06:00:00Z": { "apdex": 1 },
      "2023-03-12T07:00:00Z": { "apdex": 0.51 }
    }`))

	c.Assert(err, IsNil)
	c.Assert(p.Metrics, HasLen, 6)
	c.Assert(p.Metrics[0].Apdex, Equals, 0.975)
	c.Assert(p.Metrics[5].Apdex, Equals, 0.51)

	err = p.UnmarshalJSON([]byte(`ABCD`))
	c.Assert(err, NotNil)

	err = p.UnmarshalJSON([]byte(`{"2023-03-12K02:00:00Z": { "apdex": 0.975 }}`))
	c.Assert(err, NotNil)
}

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *UpdownSuite) TestWebhookParseError(c *C) {
	_, err := ParseWebhook([]byte(`FFFF`))

	c.Assert(err, ErrorMatches, `invalid character 'F' looking for beginning of value`)

	wh, err := ParseWebhook([]byte(`[{"event": "check.unknown"}]`))

	c.Assert(err, IsNil)
	c.Assert(wh, HasLen, 0)
}

func (s *UpdownSuite) TestWebhookDown(c *C) {
	wh, err := ParseWebhook([]byte(`[{
  "event": "check.down",
  "time": "2025-02-14T09:26:44Z",
  "description": "DOWN: https://updown.io/ since 12:16:44 (MSK), reason: 418 I'm a teapot",
  "check": {},
  "downtime": {
    "id": "67af0c5479903903b4c091b2",
    "details_url": "https://updown.io/downtimes/67af0c5479903903b4c091b2",
    "error": "418 I'm a teapot",
    "started_at": "2025-02-14T09:16:44Z",
    "ended_at": null,
    "duration": null,
    "partial": null
  }
}]`))

	c.Assert(err, IsNil)
	c.Assert(wh, HasLen, 1)

	c.Assert(wh[0].Type, Equals, EVENT_DOWN)

	ev, ok := wh[0].Event.(*EventDown)

	c.Assert(ok, Equals, true)
	c.Assert(ev.Type, Equals, EVENT_DOWN)
	c.Assert(ev.Time.Unix(), Equals, int64(1739525204))
	c.Assert(ev.Description, Equals, "DOWN: https://updown.io/ since 12:16:44 (MSK), reason: 418 I'm a teapot")
	c.Assert(ev.Downtime, NotNil)
	c.Assert(ev.Downtime.ID, Equals, "67af0c5479903903b4c091b2")
	c.Assert(ev.Downtime.DetailsURL, Equals, "https://updown.io/downtimes/67af0c5479903903b4c091b2")
	c.Assert(ev.Downtime.Error, Equals, "418 I'm a teapot")
	c.Assert(ev.Downtime.StartedAt.Unix(), Equals, int64(1739524604))
	c.Assert(ev.Downtime.EndedAt.IsZero(), Equals, true)
	c.Assert(ev.Downtime.Duration, Equals, 0)
	c.Assert(ev.Downtime.IsPartial, Equals, false)
}

func (s *UpdownSuite) TestWebhookUp(c *C) {
	wh, err := ParseWebhook([]byte(`[{
  "event": "check.up",
  "time": "2025-02-14T09:26:44Z",
  "description": "UP: https://updown.io/ since 12:26:29 (MSK), after being down for 10 minutes, reason: 418 I'm a teapot",
  "check": {},
  "downtime": {
    "id": "67af0c5479903903b4c091b4",
    "details_url": "https://updown.io/downtimes/67af0c5479903903b4c091b4",
    "error": "418 I'm a teapot",
    "started_at": "2025-02-14T09:16:44Z",
    "ended_at": "2025-02-14T09:26:29Z",
    "duration": 585,
    "partial": null
  }
}]`))

	c.Assert(err, IsNil)
	c.Assert(wh, HasLen, 1)

	c.Assert(wh[0].Type, Equals, EVENT_UP)

	ev, ok := wh[0].Event.(*EventUp)

	c.Assert(ok, Equals, true)
	c.Assert(ev.Type, Equals, EVENT_UP)
	c.Assert(ev.Time.Unix(), Equals, int64(1739525204))
	c.Assert(ev.Description, Equals, "UP: https://updown.io/ since 12:26:29 (MSK), after being down for 10 minutes, reason: 418 I'm a teapot")
	c.Assert(ev.Downtime, NotNil)
	c.Assert(ev.Downtime.ID, Equals, "67af0c5479903903b4c091b4")
	c.Assert(ev.Downtime.DetailsURL, Equals, "https://updown.io/downtimes/67af0c5479903903b4c091b4")
	c.Assert(ev.Downtime.Error, Equals, "418 I'm a teapot")
	c.Assert(ev.Downtime.StartedAt.Unix(), Equals, int64(1739524604))
	c.Assert(ev.Downtime.EndedAt.Unix(), Equals, int64(1739525189))
	c.Assert(ev.Downtime.Duration, Equals, 585)
	c.Assert(ev.Downtime.IsPartial, Equals, false)
}

func (s *UpdownSuite) TestWebhookSSLInvalid(c *C) {
	wh, err := ParseWebhook([]byte(`[{
  "event": "check.ssl_invalid",
  "time": "2025-02-14T09:26:44Z",
  "description": "The SSL certificate served by updown.io is not valid (error code 20: unable to get local issuer certificate)",
  "check": {},
  "ssl": {
    "cert": {
      "subject": "updown.io",
      "issuer": "Let's Encrypt Authority X3 (Let's Encrypt)",
      "from": "2018-09-08T21:00:18Z",
      "to": "2018-12-07T21:00:18Z",
      "algorithm": "SHA-256 with RSA encryption"
    },
    "error": "error code 20: unable to get local issuer certificate"
  }
}]`))

	c.Assert(err, IsNil)
	c.Assert(wh, HasLen, 1)

	c.Assert(wh[0].Type, Equals, EVENT_SSL_INVALID)

	ev, ok := wh[0].Event.(*EventSSLInvalid)

	c.Assert(ok, Equals, true)
	c.Assert(ev.Type, Equals, EVENT_SSL_INVALID)
	c.Assert(ev.Time.Unix(), Equals, int64(1739525204))
	c.Assert(ev.Description, Equals, "The SSL certificate served by updown.io is not valid (error code 20: unable to get local issuer certificate)")
	c.Assert(ev.SSL, NotNil)
	c.Assert(ev.SSL.Cert, NotNil)
	c.Assert(ev.SSL.Cert.Subject, Equals, "updown.io")
	c.Assert(ev.SSL.Cert.Issuer, Equals, "Let's Encrypt Authority X3 (Let's Encrypt)")
	c.Assert(ev.SSL.Cert.From.Unix(), Equals, int64(1536440418))
	c.Assert(ev.SSL.Cert.To.Unix(), Equals, int64(1544216418))
	c.Assert(ev.SSL.Cert.Algorithm, Equals, "SHA-256 with RSA encryption")
	c.Assert(ev.SSL.DaysBeforeExpiration, Equals, 0)
	c.Assert(ev.SSL.Error, Equals, "error code 20: unable to get local issuer certificate")
}

func (s *UpdownSuite) TestWebhookSSLValid(c *C) {
	wh, err := ParseWebhook([]byte(`[{
  "event": "check.ssl_valid",
  "time": "2025-02-14T09:26:44Z",
  "description": "The SSL certificate served by updown.io is now valid",
  "check": {},
  "ssl": {
    "cert": {
      "subject": "updown.io",
      "issuer": "Let's Encrypt Authority X3 (Let's Encrypt)",
      "from": "2018-09-08T21:00:18Z",
      "to": "2018-12-07T21:00:18Z",
      "algorithm": "SHA-256 with RSA encryption"
    }
  }
}]`))

	c.Assert(err, IsNil)
	c.Assert(wh, HasLen, 1)

	c.Assert(wh[0].Type, Equals, EVENT_SSL_VALID)

	ev, ok := wh[0].Event.(*EventSSLValid)

	c.Assert(ok, Equals, true)
	c.Assert(ev.Type, Equals, EVENT_SSL_VALID)
	c.Assert(ev.Time.Unix(), Equals, int64(1739525204))
	c.Assert(ev.Description, Equals, "The SSL certificate served by updown.io is now valid")
	c.Assert(ev.SSL, NotNil)
	c.Assert(ev.SSL.Cert, NotNil)
	c.Assert(ev.SSL.Cert.Subject, Equals, "updown.io")
	c.Assert(ev.SSL.Cert.Issuer, Equals, "Let's Encrypt Authority X3 (Let's Encrypt)")
	c.Assert(ev.SSL.Cert.From.Unix(), Equals, int64(1536440418))
	c.Assert(ev.SSL.Cert.To.Unix(), Equals, int64(1544216418))
	c.Assert(ev.SSL.Cert.Algorithm, Equals, "SHA-256 with RSA encryption")
	c.Assert(ev.SSL.DaysBeforeExpiration, Equals, 0)
	c.Assert(ev.SSL.Error, Equals, "")
}

func (s *UpdownSuite) TestWebhookSSLExpiration(c *C) {
	wh, err := ParseWebhook([]byte(`[{
  "event": "check.ssl_expiration",
  "time": "2025-02-14T09:26:44Z",
  "description": "The SSL certificate served by updown.io will expire in 7 days",
  "check": {},
  "ssl": {
    "cert": {
      "subject": "updown.io",
      "issuer": "Let's Encrypt Authority X3 (Let's Encrypt)",
      "from": "2018-09-08T21:00:18Z",
      "to": "2018-12-07T21:00:18Z",
      "algorithm": "SHA-256 with RSA encryption"
    },
    "days_before_expiration": 7
  }
}]`))

	c.Assert(err, IsNil)
	c.Assert(wh, HasLen, 1)

	c.Assert(wh[0].Type, Equals, EVENT_SSL_EXPIRTAION)

	ev, ok := wh[0].Event.(*EventSSLExpiration)

	c.Assert(ok, Equals, true)
	c.Assert(ev.Type, Equals, EVENT_SSL_EXPIRTAION)
	c.Assert(ev.Time.Unix(), Equals, int64(1739525204))
	c.Assert(ev.Description, Equals, "The SSL certificate served by updown.io will expire in 7 days")
	c.Assert(ev.SSL, NotNil)
	c.Assert(ev.SSL.Cert, NotNil)
	c.Assert(ev.SSL.Cert.Subject, Equals, "updown.io")
	c.Assert(ev.SSL.Cert.Issuer, Equals, "Let's Encrypt Authority X3 (Let's Encrypt)")
	c.Assert(ev.SSL.Cert.From.Unix(), Equals, int64(1536440418))
	c.Assert(ev.SSL.Cert.To.Unix(), Equals, int64(1544216418))
	c.Assert(ev.SSL.Cert.Algorithm, Equals, "SHA-256 with RSA encryption")
	c.Assert(ev.SSL.DaysBeforeExpiration, Equals, 7)
	c.Assert(ev.SSL.Error, Equals, "")
}

func (s *UpdownSuite) TestWebhookSSLRenewed(c *C) {
	wh, err := ParseWebhook([]byte(`[{
  "event": "check.ssl_renewed",
  "time": "2025-02-14T09:26:44Z",
  "description": "The SSL certificate served by updown.io was renewed",
  "check": {},
  "ssl": {
    "new_cert": {
      "subject": "updown.io",
      "issuer": "Let's Encrypt Authority X3 (Let's Encrypt)",
      "from": "2018-09-08T21:00:18Z",
      "to": "2018-12-07T21:00:18Z",
      "algorithm": "SHA-256 with RSA encryption"
    },
    "old_cert": {
      "subject": "updown.io",
      "issuer": "Let's Encrypt Authority X3 (Let's Encrypt)",
      "from": "2018-09-08T21:00:18Z",
      "to": "2018-12-07T21:00:18Z",
      "algorithm": "SHA-256 with RSA encryption"
    }
  }
}]`))

	c.Assert(err, IsNil)
	c.Assert(wh, HasLen, 1)

	c.Assert(wh[0].Type, Equals, EVENT_SSL_RENEWED)

	ev, ok := wh[0].Event.(*EventSSLRenewed)

	c.Assert(ok, Equals, true)
	c.Assert(ev.Type, Equals, EVENT_SSL_RENEWED)
	c.Assert(ev.Time.Unix(), Equals, int64(1739525204))
	c.Assert(ev.Description, Equals, "The SSL certificate served by updown.io was renewed")
	c.Assert(ev.SSL, NotNil)
	c.Assert(ev.SSL.NewCert, NotNil)
	c.Assert(ev.SSL.OldCert, NotNil)
	c.Assert(ev.SSL.NewCert.Subject, Equals, "updown.io")
	c.Assert(ev.SSL.NewCert.Issuer, Equals, "Let's Encrypt Authority X3 (Let's Encrypt)")
	c.Assert(ev.SSL.NewCert.From.Unix(), Equals, int64(1536440418))
	c.Assert(ev.SSL.NewCert.To.Unix(), Equals, int64(1544216418))
	c.Assert(ev.SSL.NewCert.Algorithm, Equals, "SHA-256 with RSA encryption")
	c.Assert(ev.SSL.OldCert.Subject, Equals, "updown.io")
	c.Assert(ev.SSL.OldCert.Issuer, Equals, "Let's Encrypt Authority X3 (Let's Encrypt)")
	c.Assert(ev.SSL.OldCert.From.Unix(), Equals, int64(1536440418))
	c.Assert(ev.SSL.OldCert.To.Unix(), Equals, int64(1544216418))
	c.Assert(ev.SSL.OldCert.Algorithm, Equals, "SHA-256 with RSA encryption")
}

func (s *UpdownSuite) TestWebhookPerformanceDrop(c *C) {
	wh, err := ParseWebhook([]byte(`[{
  "event": "check.performance_drop",
  "time": "2025-02-14T09:26:44Z",
  "description": "Apdex of https://updown.io/ dropped 47%",
  "check": {},
  "apdex_dropped": "47%",
  "last_metrics": {
    "2023-03-12T02:00:00Z": { "apdex": 0.975 },
    "2023-03-12T03:00:00Z": { "apdex": 1 },
    "2023-03-12T04:00:00Z": { "apdex": 0.98 },
    "2023-03-12T05:00:00Z": { "apdex": 1 },
    "2023-03-12T06:00:00Z": { "apdex": 1 },
    "2023-03-12T07:00:00Z": { "apdex": 0.51 }
  }
}]`))

	c.Assert(err, IsNil)
	c.Assert(wh, HasLen, 1)

	c.Assert(wh[0].Type, Equals, EVENT_PERFORMANCE_DROP)

	ev, ok := wh[0].Event.(*EventPerformanceDrop)

	c.Assert(ok, Equals, true)
	c.Assert(ev.Type, Equals, EVENT_PERFORMANCE_DROP)
	c.Assert(ev.Time.Unix(), Equals, int64(1739525204))
	c.Assert(ev.Description, Equals, "Apdex of https://updown.io/ dropped 47%")
	c.Assert(ev.ApdexDropped, Equals, "47%")
	c.Assert(ev.LastMetrics, NotNil)
	c.Assert(ev.LastMetrics.Metrics, HasLen, 6)
	c.Assert(ev.LastMetrics.Metrics[0].Date.Unix(), Equals, int64(1678586400))
	c.Assert(ev.LastMetrics.Metrics[0].Apdex, Equals, 0.975)
	c.Assert(ev.LastMetrics.Metrics[5].Date.Unix(), Equals, int64(1678604400))
	c.Assert(ev.LastMetrics.Metrics[5].Apdex, Equals, 0.51)
}

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *UpdownSuite) TestBasicErrors(c *C) {
	var api *Client

	api.SetUserAgent("test", "1")

	c.Assert(api.Calls(), Equals, uint(0))

	_, err := api.GetChecks()
	c.Assert(err, NotNil)

	_, err = api.GetCheck("ngg8", false)
	c.Assert(err, NotNil)

	_, err = api.GetDowntimes("ngg8", false)
	c.Assert(err, NotNil)

	_, err = api.GetMetrics("ngg8", MetricsOptions{})
	c.Assert(err, NotNil)

	_, err = api.GetNodes()
	c.Assert(err, NotNil)

	_, err = api.GetNodesIPs()
	c.Assert(err, NotNil)

	_, err = api.GetNodesIPsV4()
	c.Assert(err, NotNil)

	_, err = api.GetNodesIPsV6()
	c.Assert(err, NotNil)

	_, err = api.GetRecipients()
	c.Assert(err, NotNil)

	_, err = api.GetStatusPages()
	c.Assert(err, NotNil)

	api, err = NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	_, err = api.GetCheck("", false)
	c.Assert(err, NotNil)

	_, err = api.GetDowntimes("", false)
	c.Assert(err, NotNil)

	_, err = api.GetMetrics("", MetricsOptions{})
	c.Assert(err, NotNil)
}

func (s *UpdownSuite) TestAPINewClient(c *C) {
	api, err := NewClient("")

	c.Assert(err, NotNil)
	c.Assert(api, IsNil)

	api, err = NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	api.SetUserAgent("UpdownTest", "1.0.0")
}

func (s *UpdownSuite) TestAPIHTTPErrors(c *C) {
	api, err := NewClient("http-error")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	apiURL = "http://127.0.0.1:9999"

	_, err = api.GetChecks()
	c.Assert(err, NotNil)

	apiURL = "http://127.0.0.1:" + TEST_PORT

	_, err = api.GetChecks()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetCheck("ngg8", false)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetDowntimes("ngg8", false)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetMetrics("ngg8", MetricsOptions{})
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetNodes()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetNodesIPs()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetNodesIPsV4()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetNodesIPsV6()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetRecipients()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")

	_, err = api.GetStatusPages()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "API returned non-ok status code 503")
}

func (s *UpdownSuite) TestAPIDataErrors(c *C) {
	api, err := NewClient("data-error")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	_, err = api.GetChecks()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetCheck("ngg8", false)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetDowntimes("ngg8", false)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetMetrics("ngg8", MetricsOptions{})
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetNodes()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetNodesIPs()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetNodesIPsV4()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetNodesIPsV6()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetRecipients()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")

	_, err = api.GetStatusPages()
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, "Can't decode API response: invalid character 'F' looking for beginning of value")
}

func (s *UpdownSuite) TestGetChecks(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	checks, err := api.GetChecks()

	c.Assert(err, IsNil)
	c.Assert(checks, HasLen, 1)

	checkInfo := checks[0]

	c.Assert(checkInfo.Token, Equals, "ngg8")
	c.Assert(checkInfo.URL, Equals, "https://updown.io")
	c.Assert(checkInfo.LastStatus, Equals, 200)
	c.Assert(checkInfo.Uptime, Equals, 100.0)
	c.Assert(checkInfo.IsDown, Equals, false)
	c.Assert(checkInfo.UpSince.Unix(), Equals, int64(1703322411))
	c.Assert(checkInfo.Error, Equals, "")
	c.Assert(checkInfo.Period, Equals, 15)
	c.Assert(checkInfo.Apdex, Equals, 0.5)
	c.Assert(checkInfo.StringMatch, Equals, "")
	c.Assert(checkInfo.IsEnabled, Equals, true)
	c.Assert(checkInfo.IsPublished, Equals, true)
	c.Assert(checkInfo.DisabledLocations, HasLen, 0)
	c.Assert(checkInfo.Recipients, HasLen, 2)
	c.Assert(checkInfo.LastCheckAt.Unix(), Equals, int64(1639717201))
	c.Assert(checkInfo.NextCheckAt.Unix(), Equals, int64(1639717216))
	c.Assert(checkInfo.CreatedAt.Unix(), Equals, int64(1348320584))
	c.Assert(checkInfo.MuteUntil.IsZero(), Equals, true)
	c.Assert(checkInfo.FaviconURL, Equals, "https://updown.io/favicon.png")
	c.Assert(checkInfo.CustomHeaders, HasLen, 0)
	c.Assert(checkInfo.HTTPVerb, Equals, "GET/HEAD")
	c.Assert(checkInfo.HTTPBody, Equals, "")
	c.Assert(checkInfo.SSL, NotNil)
	c.Assert(checkInfo.SSL.TestedAt.Unix(), Equals, int64(1639717084))
	c.Assert(checkInfo.SSL.ExpiresAt.Unix(), Equals, int64(1645459056))
	c.Assert(checkInfo.SSL.IsValid, Equals, true)
	c.Assert(checkInfo.SSL.Error, Equals, "")

	c.Assert(api.Calls(), Equals, uint(1))
}

func (s *UpdownSuite) TestGetCheck(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	checkInfo, err := api.GetCheck("ngg8", true)

	c.Assert(err, IsNil)
	c.Assert(checkInfo, NotNil)

	c.Assert(checkInfo.Token, Equals, "ngg8")
	c.Assert(checkInfo.URL, Equals, "https://updown.io")
	c.Assert(checkInfo.LastStatus, Equals, 200)
	c.Assert(checkInfo.Uptime, Equals, 100.0)
	c.Assert(checkInfo.IsDown, Equals, false)
	c.Assert(checkInfo.UpSince.Unix(), Equals, int64(1703322411))
	c.Assert(checkInfo.Error, Equals, "")
	c.Assert(checkInfo.Period, Equals, 15)
	c.Assert(checkInfo.Apdex, Equals, 0.5)
	c.Assert(checkInfo.StringMatch, Equals, "")
	c.Assert(checkInfo.IsEnabled, Equals, true)
	c.Assert(checkInfo.IsPublished, Equals, true)
	c.Assert(checkInfo.DisabledLocations, HasLen, 0)
	c.Assert(checkInfo.Recipients, HasLen, 2)
	c.Assert(checkInfo.LastCheckAt.Unix(), Equals, int64(1639717201))
	c.Assert(checkInfo.NextCheckAt.Unix(), Equals, int64(1639717216))
	c.Assert(checkInfo.CreatedAt.Unix(), Equals, int64(1348320584))
	c.Assert(checkInfo.MuteUntil.IsZero(), Equals, true)
	c.Assert(checkInfo.FaviconURL, Equals, "https://updown.io/favicon.png")
	c.Assert(checkInfo.CustomHeaders, HasLen, 0)
	c.Assert(checkInfo.HTTPVerb, Equals, "GET/HEAD")
	c.Assert(checkInfo.HTTPBody, Equals, "")
	c.Assert(checkInfo.SSL, NotNil)
	c.Assert(checkInfo.SSL.TestedAt.Unix(), Equals, int64(1639717084))
	c.Assert(checkInfo.SSL.ExpiresAt.Unix(), Equals, int64(1645459056))
	c.Assert(checkInfo.SSL.IsValid, Equals, true)
	c.Assert(checkInfo.SSL.Error, Equals, "")
}

func (s *UpdownSuite) TestGetDowntimes(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	downtimes, err := api.GetDowntimes("ngg8", true)

	c.Assert(err, IsNil)
	c.Assert(downtimes, HasLen, 2)

	c.Assert(downtimes[0].ID, Equals, "66f255685d3c15c3bbe8fd6e")
	c.Assert(downtimes[0].DetailsURL, Equals, "https://updown.io/downtimes/66f255685d3c15c3bbe8fd6e")
	c.Assert(downtimes[0].Error, Equals, "Connection timeout (10 seconds)")
	c.Assert(downtimes[0].StartedAt.Unix(), Equals, int64(1727157572))
	c.Assert(downtimes[0].EndedAt.Unix(), Equals, int64(1727165168))
	c.Assert(downtimes[0].Duration, Equals, 7596)
	c.Assert(downtimes[0].IsPartial, Equals, false)

	c.Assert(downtimes[1].ID, Equals, "66f2541c4fe3629362cb5120")
	c.Assert(downtimes[1].DetailsURL, Equals, "https://updown.io/downtimes/66f2541c4fe3629362cb5120")
	c.Assert(downtimes[1].Error, Equals, "TLS handshake timeout (10 seconds)")
	c.Assert(downtimes[1].StartedAt.Unix(), Equals, int64(1727157194))
	c.Assert(downtimes[1].EndedAt.Unix(), Equals, int64(1727157397))
	c.Assert(downtimes[1].Duration, Equals, 203)
	c.Assert(downtimes[1].IsPartial, Equals, false)
}

func (s *UpdownSuite) TestGetMetrics(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	metrics, err := api.GetMetrics("ngg8", MetricsOptions{
		From:    time.Now().Add(-24 * time.Hour),
		To:      time.Now(),
		GroupBy: "host",
	})

	c.Assert(err, IsNil)
	c.Assert(metrics, NotNil)

	c.Assert(metrics.Uptime, Equals, 99.999)
	c.Assert(metrics.Apdex, Equals, 0.999)
	c.Assert(metrics.Timings.Redirect, Equals, 0)
	c.Assert(metrics.Timings.NameLookup, Equals, 9)
	c.Assert(metrics.Timings.Connection, Equals, 88)
	c.Assert(metrics.Timings.Handshake, Equals, 183)
	c.Assert(metrics.Timings.Response, Equals, 90)
	c.Assert(metrics.Timings.Total, Equals, 370)
	c.Assert(metrics.Requests.Samples, Equals, 87441)
	c.Assert(metrics.Requests.Failures, Equals, 2)
	c.Assert(metrics.Requests.Satisfied, Equals, 87357)
	c.Assert(metrics.Requests.Tolerated, Equals, 77)
	c.Assert(metrics.Requests.ByResponseTime.Under125, Equals, 70521)
	c.Assert(metrics.Requests.ByResponseTime.Under250, Equals, 71126)
	c.Assert(metrics.Requests.ByResponseTime.Under500, Equals, 87357)
	c.Assert(metrics.Requests.ByResponseTime.Under1k, Equals, 87422)
	c.Assert(metrics.Requests.ByResponseTime.Under2k, Equals, 87434)
	c.Assert(metrics.Requests.ByResponseTime.Under4k, Equals, 87438)
	c.Assert(metrics.Requests.ByResponseTime.Under8k, Equals, 0)
	c.Assert(metrics.Requests.ByResponseTime.Under16k, Equals, 0)
	c.Assert(metrics.Requests.ByResponseTime.Under32k, Equals, 0)
}

func (s *UpdownSuite) TestGetNodes(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	nodes, err := api.GetNodes()

	c.Assert(err, IsNil)
	c.Assert(nodes, HasLen, 10)

	fra := nodes["fra"]

	c.Assert(fra, NotNil)
	c.Assert(fra.IP, Equals, "104.238.159.87")
	c.Assert(fra.IPv6, Equals, "2001:19f0:6c01:145::1")
	c.Assert(fra.City, Equals, "Frankfurt")
	c.Assert(fra.Country, Equals, "Germany")
	c.Assert(fra.CountryCode, Equals, "de")
	c.Assert(fra.Lat, Equals, 50.1137)
	c.Assert(fra.Lon, Equals, 8.7119)
}

func (s *UpdownSuite) TestGetNodesIPs(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	ips, err := api.GetNodesIPs()

	c.Assert(err, IsNil)
	c.Assert(ips, HasLen, 20)
	c.Assert(ips[0], Equals, "2001:19f0:6001:2c6::1")
	c.Assert(ips[1], Equals, "45.32.74.41")
}

func (s *UpdownSuite) TestGetNodesIPsV4(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	ips, err := api.GetNodesIPsV4()

	c.Assert(err, IsNil)
	c.Assert(ips, HasLen, 10)
	c.Assert(ips[0], Equals, "45.32.74.41")
	c.Assert(ips[9], Equals, "178.63.21.176")
}

func (s *UpdownSuite) TestGetNodesIPsV6(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	ips, err := api.GetNodesIPsV6()

	c.Assert(err, IsNil)
	c.Assert(ips, HasLen, 10)
	c.Assert(ips[0], Equals, "2001:19f0:6001:2c6::1")
	c.Assert(ips[9], Equals, "2a01:4f8:141:441a::2")
}

func (s *UpdownSuite) TestGetRecipients(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	recps, err := api.GetRecipients()

	c.Assert(err, IsNil)
	c.Assert(recps, HasLen, 6)

	c.Assert(recps[0].ID, Equals, "email:3719031852")
	c.Assert(recps[0].Type, Equals, "email")
	c.Assert(recps[0].Name, Equals, "tech@example.com")
	c.Assert(recps[0].Value, Equals, "Company <tech@example.com>")
}

func (s *UpdownSuite) TestGetStatusPages(c *C) {
	api, err := NewClient("test1234")

	c.Assert(err, IsNil)
	c.Assert(api, NotNil)

	pages, err := api.GetStatusPages()

	c.Assert(err, IsNil)
	c.Assert(pages, HasLen, 1)

	page := pages[0]

	c.Assert(page.Token, Equals, "3ji4k")
	c.Assert(page.URL, Equals, "https://updown.io/p/3ji4k")
	c.Assert(page.Name, Equals, "Sample status page ✨")
	c.Assert(page.Description, Equals, "This is a demonstration status page from https://updown.io.\nYou can create and customize this kind of page for your own services.")
	c.Assert(page.Visibility, Equals, "public")
	c.Assert(page.AccessKey, Equals, "")
	c.Assert(page.Checks, HasLen, 13)
}

// ////////////////////////////////////////////////////////////////////////////////// //

func checksHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") == "http-error" {
		rw.WriteHeader(503)
		return
	}

	if r.Header.Get("X-API-Key") == "data-error" {
		rw.WriteHeader(200)
		rw.Write([]byte(`FFFF`))
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`[
  {
    "token": "ngg8",
    "url": "https://updown.io",
    "alias": "",
    "last_status": 200,
    "uptime": 100,
    "down": false,
    "down_since": null,
    "up_since": "2023-12-23T09:06:51Z",
    "error": null,
    "period": 15,
    "apdex_t": 0.5,
    "string_match": "",
    "enabled": true,
    "published": true,
    "disabled_locations": [],
    "recipients": ["email:1246848337", "sms:231178295"],
    "last_check_at": "2021-12-17T05:00:01Z",
    "next_check_at": "2021-12-17T05:00:16Z",
    "created_at": "2012-09-22T13:29:44Z",
    "mute_until": null,
    "favicon_url": "https://updown.io/favicon.png",
    "custom_headers": {},
    "http_verb": "GET/HEAD",
    "http_body": "",
    "ssl": {
      "tested_at": "2021-12-17T04:58:04Z",
      "expires_at": "2022-02-21T15:57:36Z",
      "valid": true,
      "error": null
    }
  }
]`))
}

func checkHandler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`{
  "token": "ngg8",
  "url": "https://updown.io",
  "alias": "",
  "last_status": 200,
  "uptime": 100,
  "down": false,
  "down_since": null,
  "up_since": "2023-12-23T09:06:51Z",
  "error": null,
  "period": 15,
  "apdex_t": 0.5,
  "string_match": "",
  "enabled": true,
  "published": true,
  "disabled_locations": [],
  "recipients": ["email:1246848337", "sms:231178295"],
  "last_check_at": "2021-12-17T05:00:01Z",
  "next_check_at": "2021-12-17T05:00:16Z",
  "created_at": "2012-09-22T13:29:44Z",
  "mute_until": null,
  "favicon_url": "https://updown.io/favicon.png",
  "custom_headers": {},
  "http_verb": "GET/HEAD",
  "http_body": "",
  "ssl": {
    "tested_at": "2021-12-17T04:58:04Z",
    "expires_at": "2022-02-21T15:57:36Z",
    "valid": true,
    "error": null
  }
}`))
}

func downtimesHandler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`[
  {
    "id": "66f255685d3c15c3bbe8fd6e",
    "details_url": "https://updown.io/downtimes/66f255685d3c15c3bbe8fd6e",
    "error": "Connection timeout (10 seconds)",
    "started_at": "2024-09-24T05:59:32Z",
    "ended_at": "2024-09-24T08:06:08Z",
    "duration": 7596,
    "partial": false
  },
  {
    "id": "66f2541c4fe3629362cb5120",
    "details_url": "https://updown.io/downtimes/66f2541c4fe3629362cb5120",
    "error": "TLS handshake timeout (10 seconds)",
    "started_at": "2024-09-24T05:53:14Z",
    "ended_at": "2024-09-24T05:56:37Z",
    "duration": 203,
    "partial": false
  }
]`))
}

func metricsHandler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`{
  "uptime": 99.999,
  "apdex": 0.999,
  "requests": {
    "samples": 87441,
    "failures": 2,
    "satisfied": 87357,
    "tolerated": 77,
    "by_response_time": {
      "under125": 70521,
      "under250": 71126,
      "under500": 87357,
      "under1000": 87422,
      "under2000": 87434,
      "under4000": 87438
    }
  },
  "timings": {
    "redirect": 0,
    "namelookup": 9,
    "connection": 88,
    "handshake": 183,
    "response": 90,
    "total": 370
  }
}`))
}

func nodesHandler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`{
  "lan": {
    "ip": "45.32.74.41",
    "ip6": "2001:19f0:6001:2c6::1",
    "city": "Los Angeles",
    "country": "US",
    "country_code": "us",
    "lat": 34.0729,
    "lng": -118.2606
  },
  "mia": {
    "ip": "104.238.136.194",
    "ip6": "2001:19f0:9002:11a::1",
    "city": "Miami",
    "country": "US",
    "country_code": "us",
    "lat": 25.8124,
    "lng": -80.2401
  },
  "bhs": {
    "ip": "192.99.37.47",
    "ip6": "2607:5300:60:4c2f::1",
    "city": "Montreal",
    "country": "Canada",
    "country_code": "ca",
    "lat": 45.315,
    "lng": -73.8779
  },
  "rbx": {
    "ip": "91.121.222.175",
    "ip6": "2001:41d0:2:85af::1",
    "city": "Roubaix",
    "country": "France",
    "country_code": "fr",
    "lat": 50.6871,
    "lng": 3.1773
  },
  "fra": {
    "ip": "104.238.159.87",
    "ip6": "2001:19f0:6c01:145::1",
    "city": "Frankfurt",
    "country": "Germany",
    "country_code": "de",
    "lat": 50.1137,
    "lng": 8.7119
  },
  "hel": {
    "ip": "135.181.102.135",
    "ip6": "2a01:4f9:c010:d5f9::1",
    "city": "Helsinki",
    "country": "Finland",
    "country_code": "fi",
    "lat": 60.17116,
    "lng": 24.93265
  },
  "sin": {
    "ip": "45.32.107.181",
    "ip6": "2001:19f0:4400:402e::1",
    "city": "Singapore",
    "country": "Singapore",
    "country_code": "sg",
    "lat": 1.2855,
    "lng": 103.8565
  },
  "tok": {
    "ip": "45.76.104.117",
    "ip6": "2001:19f0:7001:45a::1",
    "city": "Tokyo",
    "country": "Japan",
    "country_code": "jp",
    "lat": 35.5833,
    "lng": 139.7483
  },
  "syd": {
    "ip": "45.63.29.207",
    "ip6": "2001:19f0:5801:1d8::1",
    "city": "Sydney",
    "country": "Australia",
    "country_code": "au",
    "lat": -33.9032,
    "lng": 150.9677
  },
  "fal": {
    "ip": "178.63.21.176",
    "ip6": "2a01:4f8:141:441a::2",
    "city": "Falkenstein",
    "country": "Germany",
    "country_code": "de",
    "lat": 50.47914,
    "lng": -12.33547
  }
}`))
}

func ipsHandler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`[
  "2001:19f0:6001:2c6::1",
  "45.32.74.41",
  "2001:19f0:9002:11a::1",
  "104.238.136.194",
  "2607:5300:60:4c2f::1",
  "192.99.37.47",
  "2001:41d0:2:85af::1",
  "91.121.222.175",
  "2001:19f0:6c01:145::1",
  "104.238.159.87",
  "2a01:4f9:c010:d5f9::1",
  "135.181.102.135",
  "2001:19f0:4400:402e::1",
  "45.32.107.181",
  "2001:19f0:7001:45a::1",
  "45.76.104.117",
  "2001:19f0:5801:1d8::1",
  "45.63.29.207",
  "2a01:4f8:141:441a::2",
  "178.63.21.176"
]`))
}

func ipV4Handler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`[
  "45.32.74.41",
  "104.238.136.194",
  "192.99.37.47",
  "91.121.222.175",
  "104.238.159.87",
  "135.181.102.135",
  "45.32.107.181",
  "45.76.104.117",
  "45.63.29.207",
  "178.63.21.176"
]`))
}

func ipV6Handler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`[
  "2001:19f0:6001:2c6::1",
  "2001:19f0:9002:11a::1",
  "2607:5300:60:4c2f::1",
  "2001:41d0:2:85af::1",
  "2001:19f0:6c01:145::1",
  "2a01:4f9:c010:d5f9::1",
  "2001:19f0:4400:402e::1",
  "2001:19f0:7001:45a::1",
  "2001:19f0:5801:1d8::1",
  "2a01:4f8:141:441a::2"
]`))
}

func recipientsHandler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`[
  {
    "id": "email:3719031852",
    "type": "email",
    "name": "tech@example.com",
    "value": "Company <tech@example.com>"
  },
  {
    "id": "sms:231178295",
    "type": "sms",
    "name": "+33123456789",
    "value": "+33123456789"
  },
  {
    "id": "slack:2734790322",
    "type": "slack",
    "name": "mycompany#monitoring"
  },
  {
    "id": "telegram:4147979801",
    "type": "telegram",
    "name": "Adrien Rey-Jarthon"
  },
  {
    "id": "webhook:1159873859",
    "type": "webhook",
    "name": "My proxy",
    "value": "https://example.com/updown-endpoint"
  },
  {
    "id": "zapier:2082375816",
    "type": "zapier",
    "name": "Send alerts to Teams"
  }
]`))
}

func statusPagesHandler(rw http.ResponseWriter, r *http.Request) {
	if writeErrorResponse(rw, r) {
		return
	}

	rw.WriteHeader(200)
	rw.Write([]byte(`[
  {
    "token": "3ji4k",
    "url": "https://updown.io/p/3ji4k",
    "name": "Sample status page ✨",
    "description": "This is a demonstration status page from https://updown.io.\nYou can create and customize this kind of page for your own services.",
    "visibility": "public",
    "access_key": null,
    "checks": ["ngg8", "dmbe", "9e75", "l7ua", "6xjq", "wxax", "afha", "5yfe", "4osx", "1mjm", "sh6n", "5njh", "b1uc"]
  }
]`))
}

func writeErrorResponse(rw http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-API-Key") == "http-error" {
		rw.WriteHeader(503)
		return true
	}

	if r.Header.Get("X-API-Key") == "data-error" {
		rw.WriteHeader(200)
		rw.Write([]byte(`FFFF`))
		return true
	}

	return false
}
