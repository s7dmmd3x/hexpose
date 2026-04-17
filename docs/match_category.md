# Match Categorisation

`hexpose.match_category` groups detected secrets into broad families, making it easier to prioritise remediation by secret type.

## Categories

| Category | Examples |
|---|---|
| `cloud` | AWS, GCP, Azure credentials |
| `vcs` | GitHub, GitLab, Bitbucket tokens |
| `auth_token` | JWT, Bearer, OAuth tokens |
| `credential` | Passwords, secrets |
| `api_key` | Generic API keys |
| `cryptographic` | RSA, SSH, private keys |
| `unknown` | Anything not matched above |

Category assignment is based on keywords found in the pattern name.

## Usage

```python
from hexpose.match_category import categorise_match, categorise_all, group_by_category

# Single match
cm = categorise_match(match)
print(cm.category)   # e.g. "cloud"
print(cm.as_dict())

# All matches from a scan result
cms = categorise_all(result.matches)

# Group matches by category
groups = group_by_category(result.matches)
for category, matches in groups.items():
    print(f"{category}: {len(matches)} match(es)")
```

## Report Formatting

```python
from hexpose.category_report import format_category_report, category_summary

print(format_category_report(cms, colour=True))
print(category_summary(result.matches))
```

`category_summary` returns a compact text block counting matches per category, suitable for appending to CLI output.
