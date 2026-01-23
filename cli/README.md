# saharo-cli

Install (dev):
```bash
pip install -e saharo_client -e saharo_cli
```

## Host bootstrap

Safe overwrite (keeps Postgres data):
```bash
saharo host bootstrap --force ...
```

Dangerous full wipe (irreversible):
```bash
saharo host bootstrap --wipe-data --yes --confirm-wipe ...
```

## License activation

Activate a license and store registry credentials:
```bash
saharo auth activate
```

Check activation status:
```bash
saharo auth status
```

Log out (clears token and registry credentials):
```bash
saharo auth logout
```

Override license API URL for local development:
```bash
SAHARO_LICENSE_API_URL=http://127.0.0.1:8030 saharo auth activate
```

Bootstrap/install versions are resolved from the saharo-license releases DB via `/v1/entitlements`.

## Diagnostics and updates

Check hub compatibility and update status:
```bash
saharo health
```

Update the CLI using license API artifacts:
```bash
saharo self update
```
