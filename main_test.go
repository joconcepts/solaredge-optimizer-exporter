package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestScrape(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	var challenge, session string
	logins, broken := 0, false

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		challenge = r.URL.Query().Get("code_challenge")
		http.SetCookie(w, &http.Cookie{Name: "cognito", Value: "x", Quoted: true})
		fmt.Fprint(w, `<input type="hidden" name="csrf" value="a&#x2F;b="/>`)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("cognito"); err != nil || r.FormValue("csrf") != "a/b=" || r.FormValue("password") != "p&w" {
			fmt.Fprint(w, "try again")
			return
		}
		http.Redirect(w, r, "/mfe/auth/callback?code=c0de", http.StatusFound)
	})
	mux.HandleFunc("POST /oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if r.FormValue("code") != "c0de" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"access_token":"t"}`)
	})
	mux.HandleFunc("POST /services/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if b, _ := io.ReadAll(r.Body); string(b) != `{"access_token":"t"}` {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		logins++
		session = strconv.Itoa(logins)
		http.SetCookie(w, &http.Cookie{Name: "session", Value: session, Path: "/"})
	})
	serve := func(pattern, body string) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if c, err := r.Cookie("session"); err != nil || c.Value != session {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if broken {
				http.Error(w, "broken", http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, body)
		})
	}
	serve("GET /services/layout/logical/generic/v2/site/1", `{"siteStructure":{"type":"SITE","children":[{"type":"INVERTER","serial":"INV","children":[
		{"type":"STRING","name":"String 1.1","order":1,"children":[{"type":"OPTIMIZER","serial":"A","name":"Optimizer 1.1.1"},{"type":"OPTIMIZER","serial":"B"},{"type":"OPTIMIZER","serial":"C"},{"type":"OPTIMIZER","serial":"D"},{"type":"OPTIMIZER","serial":"E"}]}]}]}}`)
	serve("POST /services/layout/information/optimizers", `{"basicInformationList":[{"serial":"A","model":"S500B","modules":[{"tilt":0.1624325814,"manufacturer":"He\"ck","stcPower":445}]}],
		"serialToLiveData":{"A":{"lastMeasurement":"2026-11-24T19:29:31Z","current_A":0.00625,"power_W":0.18},
		"C":{"lastMeasurement":"2026-11-24T15:11:09Z","current_A":1,"optimizerVoltage_V":80,"power_W":2,"voltage_V":28,"total_last_telemetry_energy_WH":1.5},
		"D":{"current_A":1,"power_W":2},
		"E":{"lastMeasurement":"2026-11-24T19:09:31.389468296Z","power_W":3}}}`)
	serve("GET /services/layout/information/site/1", `{"peakPower":18.245,"siteTime":"2026-11-24T20:39:31.389468296+01:00"}`)
	serve("GET /services/layout/energy/site/1", `{"energy":5916}`)
	mux.HandleFunc("GET /services/layout/energy/site/1/by-inverter", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Get("start-date") != "2026-11-24" || q.Get("inverter-serials") != "INV" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"inverters":[{"serial":"INV","energy":{"value":5940,"unit":"watt-hour"},
			"strings":[{"energy":{"value":2146.25,"unit":"watt-hour"},"stringRelativeOrder":1}],
			"optimizers":[{"serial":"A","energy":{"value":188.5,"unit":"watt-hour"},"temperature":{"temperature":4,"temperatureUnit":"CELSIUS"}},
				{"serial":"C","energy":{"value":50,"unit":"watt-hour"}},{"serial":"B","energy":{"value":1,"unit":"parsec"}}]}]}`)
	})

	c := newClient()
	c.loginURL, c.portalURL = srv.URL, srv.URL
	if err := c.login(t.Context(), "u", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}

	e := &exporter{client: c, username: "u", password: "p&w", site: 1, staleAfter: 30 * time.Minute}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Errorf("before the first poll: got %d %q, want an empty page", w.Code, w.Body)
	}
	poll := func(wantLogins int) string {
		t.Helper()
		if err := e.poll(t.Context()); err != nil {
			t.Fatal(err)
		}
		if logins != wantLogins {
			t.Fatalf("got %d logins, want %d", logins, wantLogins)
		}
		w := httptest.NewRecorder()
		e.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
		return w.Body.String()
	}
	page := poll(1)
	const a = `{site="1",inverter="INV",string="String 1.1",optimizer="A",name="Optimizer 1.1.1"`
	other := func(serial string) string {
		return `{site="1",inverter="INV",string="String 1.1",optimizer="` + serial + `",name=""} `
	}
	for _, want := range []string{
		// outdated
		"solaredge_optimizer_power_watts" + other("C") + "0\n",
		"solaredge_optimizer_current_amperes" + other("C") + "0\n",
		"solaredge_optimizer_voltage_volts" + other("C") + "0\n",
		"solaredge_optimizer_module_voltage_volts" + other("C") + "0\n",
		"solaredge_optimizer_last_telemetry_energy_watthours" + other("C") + "0\n",
		"solaredge_optimizer_last_measurement_timestamp_seconds" + other("C") + "1.795533069e+09\n",
		"solaredge_optimizer_energy_today_watthours" + other("C") + "50\n",
		// no timestamp
		"solaredge_optimizer_power_watts" + other("D") + "0\n",
		// exactly at the threshold
		"solaredge_optimizer_power_watts" + other("E") + "3\n",
		"solaredge_optimizer_power_watts" + a + "} 0.18\n",
		"solaredge_optimizer_energy_today_watthours" + a + "} 188.5\n",
		"solaredge_optimizer_max_temperature_celsius" + a + "} 4\n",
		"solaredge_module_info" + a + `,module="1",manufacturer="He\"ck",model="",orientation=""} 1` + "\n",
		`solaredge_string_energy_today_watthours{site="1",inverter="INV",string="String 1.1"} 2146.25` + "\n",
		`solaredge_site_energy_today_watthours{site="1"} 5916` + "\n",
		`solaredge_site_peak_power_watts{site="1"} 18245` + "\n",
		"solaredge_up 1\n",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q in:\n%s", want, page)
		}
	}
	if strings.Contains(page, `optimizer="B"`) || strings.Contains(page, "optimizer_voltage_volts"+a) {
		t.Errorf("missing data must be left out:\n%s", page)
	}
	if n := strings.Count(page, "# TYPE solaredge_module_info "); n != 1 {
		t.Errorf("got %d module_info headers", n)
	}

	poll(1) // session is reused
	session = "expired"
	poll(2) // logged in again

	broken = true
	if err := e.poll(t.Context()); err == nil {
		t.Fatal("broken server accepted")
	}
	if p := *e.page.Load(); !strings.Contains(p, "solaredge_up 0\n") || strings.Contains(p, "optimizer") {
		t.Errorf("unexpected page after failure:\n%s", p)
	}
	broken = false
	poll(3)
}
