---
sidebar_position: 2
title: Configuration
description: Configure zopp defaults using zopp.toml.
---

# Configuration

zopp can be configured using a configuration file in your project directory, eliminating the need to specify `-w`, `-p`, `-e` flags on every command.

## Configuration Files

zopp searches for configuration files in the current directory and parent directories:

1. `zopp.toml` (recommended)
2. `zopp.yaml` or `zopp.yml`
3. `zopp.json`

The first file found is used.

## Format

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="toml" label="TOML" default>

```toml
# zopp.toml
[defaults]
workspace = "mycompany"
project = "api-backend"
environment = "development"
```

  </TabItem>
  <TabItem value="yaml" label="YAML">

```yaml
# zopp.yaml
defaults:
  workspace: mycompany
  project: api-backend
  environment: development
```

  </TabItem>
  <TabItem value="json" label="JSON">

```json
{
  "defaults": {
    "workspace": "mycompany",
    "project": "api-backend",
    "environment": "development"
  }
}
```

  </TabItem>
</Tabs>

## Options

### defaults

Default values for workspace, project, and environment.

| Key | Type | Description |
|-----|------|-------------|
| `workspace` | string | Default workspace name |
| `project` | string | Default project name |
| `environment` | string | Default environment name |

All fields are optional. You can specify just the workspace, workspace and project, or all three.

## Usage

### Full configuration

With all defaults set:

```toml
[defaults]
workspace = "mycompany"
project = "api-backend"
environment = "development"
```

Commands become simple:

```bash
# These are equivalent:
zopp secret set API_KEY "secret" -w mycompany -p api-backend -e development
zopp secret set API_KEY "secret"
```

### Partial configuration

You can configure just the workspace:

```toml
[defaults]
workspace = "mycompany"
```

Then provide project and environment on the command line:

```bash
zopp secret set API_KEY "secret" -p api-backend -e development
```

### Override defaults

Command-line flags always override config file values:

```toml
# zopp.toml
[defaults]
workspace = "mycompany"
project = "api-backend"
environment = "development"  # default
```

```bash
# Uses development (from config)
zopp secret get DATABASE_URL

# Override to production
zopp secret get DATABASE_URL -e production
```

## Directory Resolution

zopp searches for configuration files up the directory tree:

```
/home/user/projects/myapp/
├── zopp.toml              # Found and used
├── src/
│   └── components/
│       └── Button.js      # Running zopp here uses ../../../zopp.toml
└── tests/
    └── test.js            # Running zopp here uses ../zopp.toml
```

## Best Practices

### 1. Commit zopp.toml

The config file contains no secrets, just names.

### 2. Use development as default

```toml
[defaults]
environment = "development"
```

This prevents accidentally modifying production secrets.

### 3. Explicit production access

Require the flag for production:

```bash
# Uses default (development)
zopp secret get DATABASE_URL

# Explicit production access
zopp secret get DATABASE_URL -e production
```

## See Also

- [Environment Variables](/zopp/reference/environment-variables) - Configure zopp via environment
- [CLI Reference](/zopp/reference/cli) - Full command documentation
