// Command solaredge-optimizer-exporter exposes the optimizer data of a
// SolarEdge site as Prometheus metrics, using the API behind the monitoring web UI.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// Public OAuth client ID of the monitoring web UI.
	clientID  = "ugfnsujd3384sshcjehaphlh3"
	userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

var csrfRe = regexp.MustCompile(`<input[^>]*name="csrf"[^>]*value="([^"]+)"`)

// errUnauthorized reports a missing or expired session.
var errUnauthorized = errors.New("unauthorized")

type node struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Serial     string `json:"serial"`
	Order      int    `json:"order"`
	Properties struct {
		Model          string   `json:"model"`
		MaxActivePower *float64 `json:"maxActivePower"`
	} `json:"properties"`
	Children []node `json:"children"`
}

type client struct {
	http                *http.Client
	loginURL, portalURL string
}

func newClient() *client {
	c := &client{
		loginURL:  "https://login.solaredge.com",
		portalURL: "https://monitoring.solaredge.com",
	}
	c.http = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// The callback carries the auth code, we redeem it ourselves.
			if strings.HasPrefix(req.URL.String(), c.redirectURI()) {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	return c
}

func (c *client) redirectURI() string { return c.portalURL + "/mfe/auth/callback" }

func (c *client) do(ctx context.Context, method, rawURL, contentType string, body []byte) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if u, err := url.Parse(rawURL); err == nil && method == http.MethodPost {
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp, data, err
}

// api calls the portal and decodes the JSON response into out, if non-nil.
func (c *client) api(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	var contentType string
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
		contentType = "application/json"
	}
	resp, data, err := c.do(ctx, method, c.portalURL+path, contentType, body)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s %s: %s: %w", method, path, resp.Status, errUnauthorized)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	return nil
}

// login starts a new session with the web UI's OAuth code + PKCE flow. It ends up in the cookie jar.
func (c *client) login(ctx context.Context, username, password string) error {
	c.http.Jar, _ = cookiejar.New(nil)    // drop the old session; never fails with nil options
	verifier := rand.Text() + rand.Text() // PKCE requires at least 43 characters
	challenge := sha256.Sum256([]byte(verifier))
	loginURL := c.loginURL + "/login?" + url.Values{
		"lang":                  {"en"},
		"response_type":         {"code"},
		"client_id":             {clientID},
		"scope":                 {"email openid"},
		"redirect_uri":          {c.redirectURI()},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
	}.Encode()

	const formType = "application/x-www-form-urlencoded"
	resp, page, err := c.do(ctx, http.MethodGet, loginURL, "", nil)
	if err != nil {
		return err
	}
	m := csrfRe.FindSubmatch(page)
	if m == nil {
		return fmt.Errorf("no login form found (%s)", resp.Status)
	}

	resp, _, err = c.do(ctx, http.MethodPost, loginURL, formType, []byte(url.Values{
		"csrf":           {html.UnescapeString(string(m[1]))},
		"username":       {username},
		"password":       {password},
		"cognitoAsfData": {""},
	}.Encode()))
	if err != nil {
		return err
	}
	location, err := resp.Location()
	if err != nil {
		return fmt.Errorf("rejected (%s at %s): wrong credentials, or MFA enabled", resp.Status, resp.Request.URL.Path)
	}
	code := location.Query().Get("code")
	if code == "" {
		return fmt.Errorf("no auth code returned: %s", location.Query().Get("error_description"))
	}

	resp, tokens, err := c.do(ctx, http.MethodPost, c.loginURL+"/oauth2/token", formType, []byte(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {c.redirectURI()},
		"code":          {code},
		"code_verifier": {verifier},
	}.Encode()))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token exchange: %s", resp.Status)
	}
	return c.api(ctx, http.MethodPost, "/services/auth/token?legacy=false", jsontext.Value(tokens), nil)
}

// collect fetches everything the layout view shows. Values are pointers
// so that missing data is left out rather than reported as zero. SolarEdge keeps
// returning the last reading, so live values older than staleAfter are zeroed.
func (c *client) collect(ctx context.Context, site int, staleAfter time.Duration) (*metrics, error) {
	const base = "/services/layout"
	m := &metrics{}
	siteLabel := strconv.Itoa(site)

	var siteInfo struct {
		Time      time.Time `json:"siteTime"`
		PeakPower *float64  `json:"peakPower"`
	}
	if err := c.api(ctx, http.MethodGet, fmt.Sprintf("%s/information/site/%d", base, site), nil, &siteInfo); err != nil {
		return nil, err
	}
	m.add("site_peak_power_watts", "Installed DC peak power.", scale(siteInfo.PeakPower, 1000), "site", siteLabel)

	var layout struct {
		Site node `json:"siteStructure"`
	}
	if err := c.api(ctx, http.MethodGet, fmt.Sprintf("%s/logical/generic/v2/site/%d?include-optimizers=true", base, site), nil, &layout); err != nil {
		return nil, err
	}
	var serials, inverters []string
	labels := map[string][]string{} // per optimizer
	stringNames := map[string]map[int]string{}
	var walk func(n node, inverter, str string)
	walk = func(n node, inverter, str string) {
		switch n.Type {
		case "INVERTER":
			inverter = n.Serial
			inverters = append(inverters, n.Serial)
			stringNames[inverter] = map[int]string{}
			m.add("inverter_info", "Inverter metadata.", new(1.0), "site", siteLabel, "inverter", n.Serial, "name", n.Name, "model", n.Properties.Model)
			m.add("inverter_max_active_power_watts", "Maximum active power of the inverter.", n.Properties.MaxActivePower, "site", siteLabel, "inverter", n.Serial)
		case "STRING":
			str = n.Name
			if names := stringNames[inverter]; names != nil {
				names[n.Order] = n.Name
			}
		case "OPTIMIZER":
			serials = append(serials, n.Serial)
			labels[n.Serial] = []string{"site", siteLabel, "inverter", inverter, "string", str, "optimizer", n.Serial, "name", n.Name}
		}
		for _, child := range n.Children {
			walk(child, inverter, str)
		}
	}
	walk(layout.Site, "", "")
	if len(serials) == 0 {
		return nil, fmt.Errorf("site %d has no optimizers", site)
	}

	var info struct {
		Basic []struct {
			Serial  string `json:"serial"`
			Model   string `json:"model"`
			Modules []struct {
				Orientation  string   `json:"orientation"`
				Tilt         *float64 `json:"tilt"`
				Azimuth      *float64 `json:"azimuth"`
				Manufacturer string   `json:"manufacturer"`
				Model        string   `json:"model"`
				STCPower     *float64 `json:"stcPower"`
			} `json:"modules"`
		} `json:"basicInformationList"`
		Live map[string]*struct {
			LastMeasurement  *time.Time `json:"lastMeasurement"`
			Current          *float64   `json:"current_A"`
			OptimizerVoltage *float64   `json:"optimizerVoltage_V"`
			Power            *float64   `json:"power_W"`
			Voltage          *float64   `json:"voltage_V"`
			LastTelemetryWh  *float64   `json:"total_last_telemetry_energy_WH"`
		} `json:"serialToLiveData"`
	}
	if err := c.api(ctx, http.MethodPost, base+"/information/optimizers", serials, &info); err != nil {
		return nil, err
	}
	for _, b := range info.Basic {
		l, ok := labels[b.Serial]
		if !ok {
			continue
		}
		m.add("optimizer_info", "Optimizer metadata.", new(1.0), slices.Concat(l, []string{"model", b.Model})...)
		for i, mod := range b.Modules {
			ml := slices.Concat(l, []string{"module", strconv.Itoa(i + 1)})
			m.add("module_info", "PV module metadata.", new(1.0), slices.Concat(ml, []string{"manufacturer", mod.Manufacturer, "model", mod.Model, "orientation", mod.Orientation})...)
			m.add("module_tilt_degrees", "Tilt of the PV module.", scale(mod.Tilt, 180/math.Pi), ml...)
			m.add("module_azimuth_degrees", "Azimuth of the PV module.", scale(mod.Azimuth, 180/math.Pi), ml...)
			m.add("module_stc_power_watts", "Rated power of the PV module under standard test conditions.", mod.STCPower, ml...)
		}
	}
	for _, serial := range serials {
		d, l := info.Live[serial], labels[serial]
		if d == nil {
			continue
		}
		factor := 0.0
		if d.LastMeasurement != nil {
			if siteInfo.Time.Sub(*d.LastMeasurement) <= staleAfter {
				factor = 1
			}
			m.add("optimizer_last_measurement_timestamp_seconds", "Time of the last measurement, also when it is outdated.", new(float64(d.LastMeasurement.Unix())), l...)
		}
		m.add("optimizer_power_watts", "Power at the last measurement, 0 if outdated.", scale(d.Power, factor), l...)
		m.add("optimizer_current_amperes", "Current at the last measurement, 0 if outdated.", scale(d.Current, factor), l...)
		m.add("optimizer_voltage_volts", "Optimizer voltage at the last measurement, 0 if outdated.", scale(d.OptimizerVoltage, factor), l...)
		m.add("optimizer_module_voltage_volts", "Module voltage at the last measurement, 0 if outdated.", scale(d.Voltage, factor), l...)
		m.add("optimizer_last_telemetry_energy_watthours", "Energy of the last telemetry, 0 if outdated.", scale(d.LastTelemetryWh, factor), l...)
	}

	// "Today" is a day in the site's time zone, not ours.
	today := siteInfo.Time.Format(time.DateOnly)
	var siteEnergy struct {
		Energy *float64 `json:"energy"`
	}
	if err := c.api(ctx, http.MethodGet, fmt.Sprintf("%s/energy/site/%d?start-date=%s&end-date=%[3]s", base, site, today), nil, &siteEnergy); err != nil {
		return nil, err
	}
	m.add("site_energy_today_watthours", "Energy produced by the site today.", siteEnergy.Energy, "site", siteLabel)
	for _, inverter := range inverters {
		var out struct {
			Inverters []struct {
				Serial  string `json:"serial"`
				Energy  energy `json:"energy"`
				Strings []struct {
					Energy energy `json:"energy"`
					Order  int    `json:"stringRelativeOrder"`
				} `json:"strings"`
				Optimizers []struct {
					Serial      string `json:"serial"`
					Energy      energy `json:"energy"`
					Temperature struct {
						Value *float64 `json:"temperature"`
						Unit  string   `json:"temperatureUnit"`
					} `json:"temperature"`
				} `json:"optimizers"`
			} `json:"inverters"`
		}
		query := url.Values{
			"start-date": {today}, "end-date": {today}, "inverter-serials": {inverter},
			"include-max-temperature": {"true"}, "include-color": {"false"},
		}
		if err := c.api(ctx, http.MethodGet, fmt.Sprintf("%s/energy/site/%d/by-inverter?%s", base, site, query.Encode()), nil, &out); err != nil {
			return nil, err
		}
		for _, inv := range out.Inverters {
			if inv.Serial != inverter {
				continue
			}
			m.add("inverter_energy_today_watthours", "Energy produced by the inverter today.", inv.Energy.wattHours(), "site", siteLabel, "inverter", inv.Serial)
			for _, str := range inv.Strings {
				name := cmp.Or(stringNames[inverter][str.Order], strconv.Itoa(str.Order))
				m.add("string_energy_today_watthours", "Energy produced by the string today.", str.Energy.wattHours(), "site", siteLabel, "inverter", inverter, "string", name)
			}
			for _, o := range inv.Optimizers {
				l, ok := labels[o.Serial]
				if !ok {
					continue
				}
				m.add("optimizer_energy_today_watthours", "Energy produced by the optimizer today.", o.Energy.wattHours(), l...)
				if o.Temperature.Unit == "CELSIUS" {
					m.add("optimizer_max_temperature_celsius", "Maximum temperature today.", o.Temperature.Value, l...)
				}
			}
		}
	}
	return m, nil
}

type energy struct {
	Value *float64 `json:"value"`
	Unit  string   `json:"unit"`
}

// wattHours returns nil for units we have not seen, instead of a wrong value.
func (e energy) wattHours() *float64 {
	if e.Unit != "watt-hour" {
		return nil
	}
	return e.Value
}

func scale(v *float64, factor float64) *float64 {
	if v == nil {
		return nil
	}
	return new(*v * factor)
}

// metrics builds the Prometheus text format, in which samples must be grouped by name.
type metrics struct {
	names    []string
	families map[string]*strings.Builder
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// add appends a gauge sample with label name/value pairs; nil values are skipped.
func (m *metrics) add(name, help string, value *float64, labels ...string) {
	if value == nil {
		return
	}
	name = "solaredge_" + name
	b := m.families[name]
	if b == nil {
		if m.families == nil {
			m.families = map[string]*strings.Builder{}
		}
		b = &strings.Builder{}
		m.families[name] = b
		m.names = append(m.names, name)
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	b.WriteString(name)
	for i := 0; i < len(labels); i += 2 {
		sep := ","
		if i == 0 {
			sep = "{"
		}
		fmt.Fprintf(b, `%s%s="%s"`, sep, labels[i], labelEscaper.Replace(strings.ToValidUTF8(labels[i+1], "?")))
	}
	if len(labels) > 0 {
		b.WriteByte('}')
	}
	fmt.Fprintf(b, " %s\n", strconv.FormatFloat(*value, 'g', -1, 64))
}

func (m *metrics) String() string {
	var b strings.Builder
	for _, name := range m.names {
		b.WriteString(m.families[name].String())
	}
	return b.String()
}

type exporter struct {
	client             *client
	username, password string
	site               int
	staleAfter         time.Duration
	loggedIn           bool
	lastSuccess        time.Time
	page               atomic.Pointer[string]
}

func (e *exporter) login(ctx context.Context) error {
	if err := e.client.login(ctx, e.username, e.password); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	e.loggedIn = true
	log.Print("logged in")
	return nil
}

// scrape reuses the session, and logs in again once if it has expired.
func (e *exporter) scrape(ctx context.Context) (*metrics, error) {
	fresh := !e.loggedIn
	if fresh {
		if err := e.login(ctx); err != nil {
			return nil, err
		}
	}
	m, err := e.client.collect(ctx, e.site, e.staleAfter)
	if errors.Is(err, errUnauthorized) && !fresh {
		e.loggedIn = false
		if err := e.login(ctx); err != nil {
			return nil, err
		}
		m, err = e.client.collect(ctx, e.site, e.staleAfter)
	}
	return m, err
}

// poll publishes a new metrics page. After a failure the page has no
// optimizer data, so outdated values don't look current.
func (e *exporter) poll(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	m, err := e.scrape(ctx)
	up := 1.0
	if err != nil {
		// An expired session may show up as something else than a 401.
		e.loggedIn = false
		m, up = &metrics{}, 0
	} else {
		e.lastSuccess = time.Now()
	}
	m.add("up", "Whether the last poll of SolarEdge succeeded.", &up)
	if !e.lastSuccess.IsZero() {
		m.add("last_success_timestamp_seconds", "Time of the last successful poll.", new(float64(e.lastSuccess.Unix())))
	}
	e.page.Store(new(m.String()))
	return err
}

// loop polls until ctx is done. Failures double the delay up to an hour, so
// that wrong credentials don't get the account locked.
func (e *exporter) loop(ctx context.Context, interval time.Duration) {
	delay := interval
	for {
		if err := e.poll(ctx); ctx.Err() != nil {
			return
		} else if err != nil {
			delay = max(interval, min(2*delay, time.Hour))
			log.Printf("poll failed, next try in %s: %v", delay, err)
		} else {
			delay = interval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (e *exporter) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	// Empty until the first poll is done.
	if page := e.page.Load(); page != nil {
		io.WriteString(w, *page)
	}
}

func run(ctx context.Context) error {
	// Environment only: command line arguments are visible to other users.
	e := &exporter{client: newClient(), username: os.Getenv("SOLAREDGE_USERNAME"), password: os.Getenv("SOLAREDGE_PASSWORD")}
	var err error
	e.site, err = strconv.Atoi(os.Getenv("SOLAREDGE_SITE_ID"))
	if e.username == "" || e.password == "" || err != nil {
		return errors.New("set SOLAREDGE_USERNAME, SOLAREDGE_PASSWORD and a numeric SOLAREDGE_SITE_ID")
	}
	interval, err := time.ParseDuration(cmp.Or(os.Getenv("SOLAREDGE_INTERVAL"), "5m"))
	if err != nil || interval < time.Minute {
		return errors.New("SOLAREDGE_INTERVAL must be a duration of at least 1m")
	}
	e.staleAfter, err = time.ParseDuration(cmp.Or(os.Getenv("SOLAREDGE_STALE_AFTER"), "30m"))
	if err != nil || e.staleAfter <= 0 {
		return errors.New("SOLAREDGE_STALE_AFTER must be a positive duration")
	}

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", e)
	srv := &http.Server{
		Addr:              cmp.Or(os.Getenv("SOLAREDGE_LISTEN"), ":9877"),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	go e.loop(ctx, interval)
	context.AfterFunc(ctx, func() { srv.Close() })
	log.Printf("listening on %s", ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}
