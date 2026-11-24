# solaredge-optimizer-exporter

Prometheus exporter for the optimizer data of a SolarEdge site. It logs in to
the [monitoring portal](https://monitoring.solaredge.com) like a browser and
reads the data of the panel layout view. Only username, password and site ID
are needed.

This uses an undocumented API that may change at any time. Accounts with MFA or
corporate sign-in are not supported.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SOLAREDGE_USERNAME` | required | Portal login |
| `SOLAREDGE_PASSWORD` | required | Portal password |
| `SOLAREDGE_SITE_ID` | required | Number after `siteId=` in the portal URL |
| `SOLAREDGE_LISTEN` | `:9877` | Listen address |
| `SOLAREDGE_INTERVAL` | `5m` | Time between polls, at least `1m` |
| `SOLAREDGE_STALE_AFTER` | `30m` | Age after which momentary values are reported as 0 |

## Running

Put the required variables in a `.env` file (`NAME=value`, without quotes), then:

```sh
docker build -t solaredge-optimizer-exporter .
docker run -d --restart unless-stopped --env-file .env -p 9877:9877 solaredge-optimizer-exporter
```

The GitHub workflow publishes the image for amd64 and arm64 as
`ghcr.io/<owner>/<repository>`: pushes to `main` as `main`, tags like `v1.2.3`
as `1.2.3`, `1.2` and `latest`.

Without Docker, export the variables and use `go run .` (Go 1.27 or newer).

Prometheus:

```yaml
scrape_configs:
  - job_name: solaredge
    static_configs:
      - targets: ["localhost:9877"]
```

`/metrics` has no authentication and contains serial numbers; don't expose it publicly.

## Behavior

- Polling runs in the background. Scrapes return the latest poll and never
  cause requests to SolarEdge. The page is empty until the first poll is done.
- The session is reused. On a 401 or 403 the exporter logs in again and retries
  once. After any other failure, the next poll starts with a new login.
- Failed polls double the delay up to one hour. `solaredge_up` is 0 and all
  site data is left out until a poll succeeds.
- SolarEdge keeps returning the last reading, e.g. at night. Outdated momentary
  values are reported as 0. This also happens when the site stops reporting, so
  check `solaredge_optimizer_last_measurement_timestamp_seconds` to tell.

## Metrics

All metrics are gauges. "Today" is the day in the site's time zone.

| Metric | Description |
|---|---|
| `solaredge_site_peak_power_watts` | Installed DC peak power. |
| `solaredge_inverter_info` | Inverter metadata. |
| `solaredge_inverter_max_active_power_watts` | Maximum active power of the inverter. |
| `solaredge_optimizer_info` | Optimizer metadata. |
| `solaredge_module_info` | PV module metadata. |
| `solaredge_module_tilt_degrees` | Tilt of the PV module. |
| `solaredge_module_azimuth_degrees` | Azimuth of the PV module. |
| `solaredge_module_stc_power_watts` | Rated power of the PV module under standard test conditions. |
| `solaredge_optimizer_last_measurement_timestamp_seconds` | Time of the last measurement, also when it is outdated. |
| `solaredge_optimizer_power_watts` | Power at the last measurement, 0 if outdated. |
| `solaredge_optimizer_current_amperes` | Current at the last measurement, 0 if outdated. |
| `solaredge_optimizer_voltage_volts` | Optimizer voltage at the last measurement, 0 if outdated. |
| `solaredge_optimizer_module_voltage_volts` | Module voltage at the last measurement, 0 if outdated. |
| `solaredge_optimizer_last_telemetry_energy_watthours` | Energy of the last telemetry, 0 if outdated. |
| `solaredge_site_energy_today_watthours` | Energy produced by the site today. |
| `solaredge_inverter_energy_today_watthours` | Energy produced by the inverter today. |
| `solaredge_string_energy_today_watthours` | Energy produced by the string today. |
| `solaredge_optimizer_energy_today_watthours` | Energy produced by the optimizer today. |
| `solaredge_optimizer_max_temperature_celsius` | Maximum temperature today. |
| `solaredge_up` | Whether the last poll of SolarEdge succeeded. |
| `solaredge_last_success_timestamp_seconds` | Time of the last successful poll. |

Optimizer and module metrics have the labels `site`, `inverter`, `string`,
`optimizer` (serial number) and `name`; module metrics also have `module`.
