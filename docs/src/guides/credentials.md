# Managing Credentials

This guide covers how to securely store, organize, and use credentials with Vultrino.

## Credential Types

Vultrino supports several credential types:

| Type | Use Case | Auth Header Format |
|------|----------|-------------------|
| `api_key` | API tokens, bearer tokens | `Authorization: Bearer <key>` |
| `basic_auth` | Username/password auth | `Authorization: Basic <base64>` |
| `oauth2` | OAuth2 flows | `Authorization: Bearer <access_token>` |
| `private_key` | SSH keys, signing keys | (used for signing, not HTTP) |

## Adding Credentials

### API Keys

Most common type for SaaS APIs:

```bash
# GitHub Personal Access Token
vultrino add --alias github-api --key ghp_xxxxxxxxxxxx

# Stripe API Key
vultrino add --alias stripe-api --key sk_live_xxxxxxxxxxxx

# OpenAI API Key
vultrino add --alias openai --key sk-xxxxxxxxxxxx

# With description
vultrino add --alias anthropic --key sk-ant-xxxx \
  --description "Claude API key for production"
```

### Basic Auth

For APIs using username/password:

```bash
vultrino add --alias jira-api --type basic_auth \
  --username user@company.com \
  --password api_token_here

vultrino add --alias jenkins --type basic_auth \
  --username admin \
  --password jenkins_token
```

### OAuth2 Credentials

For OAuth2 flows with refresh tokens:

```bash
vultrino add --alias google-api --type oauth2 \
  --client-id "xxx.apps.googleusercontent.com" \
  --client-secret "GOCSPX-xxx" \
  --refresh-token "1//xxx"
```

## Organizing Credentials

### Naming Conventions

Use a consistent naming scheme:

```
<provider>-<environment>-<scope>
```

Examples:
- `github-prod-readonly`
- `stripe-test-charges`
- `aws-staging-s3`

### Using Prefixes

Group related credentials with prefixes:

```bash
# All GitHub credentials
vultrino add --alias github-api-readonly --key ghp_read...
vultrino add --alias github-api-admin --key ghp_admin...

# All Stripe credentials
vultrino add --alias stripe-live --key sk_live...
vultrino add --alias stripe-test --key sk_test...
```

Then restrict access with role scopes:
```bash
vultrino role create github-readonly --scopes "github-*" --permissions read,execute
```

## Listing Credentials

### Basic List

```bash
vultrino list

# Output:
# ID                                    Alias           Type        Created
# 550e8400-e29b-41d4-a716-446655440000  github-api      api_key     2024-01-15
# 6ba7b810-9dad-11d1-80b4-00c04fd430c8  stripe-live     api_key     2024-01-16
```

### JSON Output

```bash
vultrino list --json | jq '.[] | select(.type == "api_key")'
```

### Via Web UI

Navigate to `/credentials` in the web interface for a visual list.

## Using Credentials

### CLI Request

```bash
vultrino request github-api https://api.github.com/user
```

### HTTP API

```bash
curl -sX POST http://localhost:7879/api/v1/execute \
     -H "Authorization: Bearer vk_your_api_key" \
     -H "Content-Type: application/json" \
     -d '{"credential": "github-api", "method": "GET", "url": "https://api.github.com/user"}'
```

### MCP (AI Agents)

The AI agent uses the credential alias:
```
AI: "Using github-api to fetch your profile..."
*Makes request without seeing actual token*
```

## Updating Credentials

Currently, to update a credential:

1. Remove the old credential:
   ```bash
   vultrino remove github-api
   ```

2. Add the new one:
   ```bash
   vultrino add --alias github-api --key ghp_newtoken
   ```

Future versions will support in-place updates.

## Deleting Credentials

### CLI

```bash
vultrino remove old-api-key
# Deleted credential: old-api-key
```

### Web UI

Click the delete button on the credentials list, then confirm.

## Security Best Practices

### 1. Use Descriptive Names

Bad:
```bash
vultrino add --alias key1 --key xxx
```

Good:
```bash
vultrino add --alias github-ci-readonly --key xxx \
  --description "Read-only token for CI pipeline"
```

### 2. Scope Credentials Narrowly

Instead of one admin key:
```bash
vultrino add --alias github-admin --key ghp_admin_all_perms
```

Create scoped credentials:
```bash
vultrino add --alias github-repos-read --key ghp_repos_read
vultrino add --alias github-actions-write --key ghp_actions_write
```

### 3. Set Expiration Reminders

Track when credentials expire:
```bash
vultrino add --alias stripe-api --key sk_live_xxx \
  --description "Expires: 2024-12-31"
```

### 4. Rotate Regularly

Set up a rotation schedule:
1. Generate new credential at source (GitHub, Stripe, etc.)
2. Add to Vultrino with new alias
3. Test the new credential
4. Update applications to use new alias
5. Delete old credential

### 5. Audit Usage

Check what's using each credential:
```bash
# View audit logs
tail -f /var/log/vultrino/audit.log | grep github-api
```

## Backup and Recovery

### Backup

The credentials file is encrypted. Back it up securely:

```bash
cp ~/.vultrino/credentials.enc ~/backup/vultrino-$(date +%Y%m%d).enc
```

### Recovery

To restore:
```bash
cp ~/backup/vultrino-20240115.enc ~/.vultrino/credentials.enc
```

You'll need the same `VULTRINO_PASSWORD` used when the backup was created.

### Export (Not Recommended)

Vultrino intentionally doesn't support exporting credentials in plaintext. This is a security feature, not a limitation.

## Troubleshooting

### "Credential not found"

- Check the alias is spelled correctly
- Verify with `vultrino list`
- Credential may have been deleted

### "Permission denied"

- Your API key may not have access to this credential
- Check role scopes: `vultrino role list`

### "Decryption error"

- Wrong `VULTRINO_PASSWORD`
- Corrupted credentials file
- Restore from backup if needed

### "Invalid credential format"

- Check credential type matches the data
- API keys shouldn't have usernames
- Basic auth requires both username and password
