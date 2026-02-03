package monitor

const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Easy Proxies API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>
      body { margin: 0; background: #f5f5f7; }
      .topbar { display: none; }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
      window.onload = () => {
        SwaggerUIBundle({
          url: '/api/openapi.json',
          dom_id: '#swagger-ui',
          presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
          layout: 'BaseLayout',
          deepLinking: true,
          persistAuthorization: true,
        });
      };
    </script>
  </body>
</html>`

func openAPISpec() map[string]any {
	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "Easy Proxies Monitor API",
			"version":     "1.0.0",
			"description": "OpenAPI document for Easy Proxies monitor endpoints.",
		},
		"servers": []map[string]any{
			{
				"url":         "/",
				"description": "Current host",
			},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "token",
					"description":  "Use management.api_token or the /api/auth token.",
				},
			},
			"schemas": map[string]any{
				"ErrorResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"error": map[string]any{"type": "string"},
					},
				},
				"AuthRequest": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"password": map[string]any{"type": "string"},
					},
				},
				"AuthResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"message":     map[string]any{"type": "string"},
						"token":       map[string]any{"type": "string"},
						"api_token":   map[string]any{"type": "string"},
						"no_password": map[string]any{"type": "boolean"},
					},
				},
				"SettingsResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"external_ip":      map[string]any{"type": "string"},
						"probe_target":     map[string]any{"type": "string"},
						"skip_cert_verify": map[string]any{"type": "boolean"},
						"proxy_username":   map[string]any{"type": "string"},
						"proxy_password":   map[string]any{"type": "string"},
						"api_token":        map[string]any{"type": "string"},
					},
				},
				"SettingsUpdate": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"external_ip":      map[string]any{"type": "string"},
						"probe_target":     map[string]any{"type": "string"},
						"skip_cert_verify": map[string]any{"type": "boolean"},
					},
				},
				"IPInfo": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"ip":           map[string]any{"type": "string"},
						"pure_score":   map[string]any{"type": "string"},
						"fraud_score":  map[string]any{"type": "string"},
						"bot_score":    map[string]any{"type": "string"},
						"shared_users": map[string]any{"type": "string"},
						"ip_attr":      map[string]any{"type": "string"},
						"ip_src":       map[string]any{"type": "string"},
						"country":      map[string]any{"type": "string"},
						"city":         map[string]any{"type": "string"},
						"location":     map[string]any{"type": "string"},
						"isp":          map[string]any{"type": "string"},
						"asn":          map[string]any{"type": "integer"},
						"source":       map[string]any{"type": "string"},
						"updated_at":   map[string]any{"type": "string", "format": "date-time"},
					},
				},
				"NodeSnapshot": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"tag":                map[string]any{"type": "string"},
						"name":               map[string]any{"type": "string"},
						"mode":               map[string]any{"type": "string"},
						"listen_address":     map[string]any{"type": "string"},
						"port":               map[string]any{"type": "integer"},
						"available":          map[string]any{"type": "boolean"},
						"initial_check_done": map[string]any{"type": "boolean"},
						"last_latency_ms":    map[string]any{"type": "integer"},
						"last_error":         map[string]any{"type": "string"},
						"failure_count":      map[string]any{"type": "integer"},
						"success_count":      map[string]any{"type": "integer"},
						"ip_info":            schemaRef("IPInfo"),
					},
				},
				"NodeListResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"nodes": map[string]any{
							"type":  "array",
							"items": schemaRef("NodeSnapshot"),
						},
					},
				},
				"NodeConfig": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":     map[string]any{"type": "string"},
						"uri":      map[string]any{"type": "string"},
						"port":     map[string]any{"type": "integer"},
						"username": map[string]any{"type": "string"},
						"password": map[string]any{"type": "string"},
					},
				},
				"ConfigNodesResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"nodes": map[string]any{
							"type":  "array",
							"items": schemaRef("NodeConfig"),
						},
					},
				},
				"MessageResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"message": map[string]any{"type": "string"},
					},
				},
				"ProbeResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"message":    map[string]any{"type": "string"},
						"latency_ms": map[string]any{"type": "integer"},
					},
				},
				"ExportResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"count": map[string]any{"type": "integer"},
						"proxies": map[string]any{
							"type":  "array",
							"items": map[string]any{"type": "string"},
						},
					},
				},
				"ExportFilterResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"count": map[string]any{"type": "integer"},
						"proxies": map[string]any{
							"type":  "array",
							"items": map[string]any{"type": "string"},
						},
					},
				},
				"SubscriptionStatus": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"enabled":          map[string]any{"type": "boolean"},
						"last_refresh":     map[string]any{"type": "string", "format": "date-time"},
						"next_refresh":     map[string]any{"type": "string", "format": "date-time"},
						"node_count":       map[string]any{"type": "integer"},
						"last_error":       map[string]any{"type": "string"},
						"refresh_count":    map[string]any{"type": "integer"},
						"is_refreshing":    map[string]any{"type": "boolean"},
						"nodes_modified":   map[string]any{"type": "boolean"},
						"progress_total":   map[string]any{"type": "integer"},
						"progress_current": map[string]any{"type": "integer"},
						"progress_nodes":   map[string]any{"type": "integer"},
						"progress_message": map[string]any{"type": "string"},
					},
				},
			},
		},
		"security": []map[string]any{
			{"bearerAuth": []string{}},
		},
		"paths": map[string]any{
			"/api/auth": map[string]any{
				"get": map[string]any{
					"summary":     "Get auth token (if no password or already authorized)",
					"security":    []any{},
					"responses":   map[string]any{"200": jsonResponse("Auth info", schemaRef("AuthResponse")), "401": jsonResponse("Unauthorized", schemaRef("ErrorResponse"))},
					"tags":        []string{"auth"},
					"description": "If no password is set, returns token directly.",
				},
				"post": map[string]any{
					"summary":   "Login to obtain session token",
					"security":  []any{},
					"tags":      []string{"auth"},
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": schemaRef("AuthRequest"),
							},
						},
					},
					"responses": map[string]any{
						"200": jsonResponse("Login success", schemaRef("AuthResponse")),
						"401": jsonResponse("Unauthorized", schemaRef("ErrorResponse")),
					},
				},
			},
			"/api/settings": map[string]any{
				"get": map[string]any{
					"summary":   "Get runtime settings",
					"tags":      []string{"settings"},
					"responses": map[string]any{"200": jsonResponse("Settings", schemaRef("SettingsResponse"))},
				},
				"put": map[string]any{
					"summary": "Update runtime settings",
					"tags":    []string{"settings"},
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": schemaRef("SettingsUpdate"),
							},
						},
					},
					"responses": map[string]any{
						"200": jsonResponse("Updated", schemaRef("SettingsResponse")),
						"400": jsonResponse("Bad request", schemaRef("ErrorResponse")),
					},
				},
			},
			"/api/nodes": map[string]any{
				"get": map[string]any{
					"summary":   "List runtime nodes",
					"tags":      []string{"nodes"},
					"responses": map[string]any{"200": jsonResponse("Node list", schemaRef("NodeListResponse"))},
				},
			},
			"/api/nodes/{tag}/probe": map[string]any{
				"post": map[string]any{
					"summary": "Probe a node",
					"tags":    []string{"nodes"},
					"parameters": []map[string]any{
						pathParam("tag", "Node tag"),
					},
					"responses": map[string]any{
						"200": jsonResponse("Probe result", schemaRef("ProbeResponse")),
						"404": jsonResponse("Not found", schemaRef("ErrorResponse")),
					},
				},
			},
			"/api/nodes/{tag}/release": map[string]any{
				"post": map[string]any{
					"summary": "Release a blacklisted node",
					"tags":    []string{"nodes"},
					"parameters": []map[string]any{
						pathParam("tag", "Node tag"),
					},
					"responses": map[string]any{
						"200": jsonResponse("Release result", schemaRef("MessageResponse")),
					},
				},
			},
			"/api/nodes/probe-all": map[string]any{
				"post": map[string]any{
					"summary": "Probe all nodes (SSE stream)",
					"tags":    []string{"nodes"},
					"parameters": []map[string]any{
						queryParam("interval_ms", "Initial interval in ms", "integer"),
						queryParam("interval_step_ms", "Interval step in ms", "integer"),
						queryParam("max_interval_ms", "Max interval in ms", "integer"),
					},
					"responses": map[string]any{
						"200": textResponse("SSE stream", "text/event-stream"),
					},
				},
			},
			"/api/export": map[string]any{
				"get": map[string]any{
					"summary": "Export available proxies",
					"tags":    []string{"export"},
					"parameters": []map[string]any{
						queryParam("format", "Response format: json or text", "string"),
					},
					"responses": map[string]any{
						"200": map[string]any{
							"description": "Proxy list",
							"content": map[string]any{
								"text/plain": map[string]any{
									"schema": map[string]any{"type": "string"},
								},
								"application/json": map[string]any{
									"schema": schemaRef("ExportResponse"),
								},
							},
						},
					},
				},
			},
			"/api/export/filter": map[string]any{
				"get": map[string]any{
					"summary": "Export proxies with filters",
					"tags":    []string{"export"},
					"parameters": []map[string]any{
						queryParam("shared_min", "Minimum shared users", "integer"),
						queryParam("shared_max", "Maximum shared users", "integer"),
						queryParam("country", "Country keyword", "string"),
						queryParam("ip_src", "IP source", "string"),
						queryParam("ip_attr", "IP attribute", "string"),
						queryParam("fraud_max", "Max fraud score", "number"),
						queryParam("pure_max", "Max pure score", "number"),
						queryParam("latency_max", "Max latency (ms)", "integer"),
					},
					"responses": map[string]any{
						"200": jsonResponse("Filtered proxies", schemaRef("ExportFilterResponse")),
					},
				},
			},
			"/api/debug": map[string]any{
				"get": map[string]any{
					"summary": "Debug info",
					"tags":    []string{"debug"},
					"responses": map[string]any{
						"200": map[string]any{"description": "Debug payload"},
					},
				},
			},
			"/api/nodes/config": map[string]any{
				"get": map[string]any{
					"summary":   "List config nodes",
					"tags":      []string{"config"},
					"responses": map[string]any{"200": jsonResponse("Config nodes", schemaRef("ConfigNodesResponse"))},
				},
				"post": map[string]any{
					"summary": "Create config node",
					"tags":    []string{"config"},
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": schemaRef("NodeConfig"),
							},
						},
					},
					"responses": map[string]any{
						"200": jsonResponse("Created", schemaRef("MessageResponse")),
						"400": jsonResponse("Bad request", schemaRef("ErrorResponse")),
					},
				},
			},
			"/api/nodes/config/{name}": map[string]any{
				"put": map[string]any{
					"summary": "Update config node",
					"tags":    []string{"config"},
					"parameters": []map[string]any{
						pathParam("name", "Node name"),
					},
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": schemaRef("NodeConfig"),
							},
						},
					},
					"responses": map[string]any{
						"200": jsonResponse("Updated", schemaRef("MessageResponse")),
						"400": jsonResponse("Bad request", schemaRef("ErrorResponse")),
					},
				},
				"delete": map[string]any{
					"summary": "Delete config node",
					"tags":    []string{"config"},
					"parameters": []map[string]any{
						pathParam("name", "Node name"),
					},
					"responses": map[string]any{
						"200": jsonResponse("Deleted", schemaRef("MessageResponse")),
						"404": jsonResponse("Not found", schemaRef("ErrorResponse")),
					},
				},
			},
			"/api/reload": map[string]any{
				"post": map[string]any{
					"summary":   "Reload configuration",
					"tags":      []string{"config"},
					"responses": map[string]any{"200": jsonResponse("Reloaded", schemaRef("MessageResponse"))},
				},
			},
			"/api/subscription/status": map[string]any{
				"get": map[string]any{
					"summary":   "Subscription refresh status",
					"tags":      []string{"subscription"},
					"responses": map[string]any{"200": jsonResponse("Status", schemaRef("SubscriptionStatus"))},
				},
			},
			"/api/subscription/refresh": map[string]any{
				"post": map[string]any{
					"summary":   "Trigger subscription refresh",
					"tags":      []string{"subscription"},
					"responses": map[string]any{"200": jsonResponse("Refresh result", schemaRef("MessageResponse"))},
				},
			},
		},
	}
}

func schemaRef(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func jsonResponse(desc string, schema any) map[string]any {
	return map[string]any{
		"description": desc,
		"content": map[string]any{
			"application/json": map[string]any{
				"schema": schema,
			},
		},
	}
}

func textResponse(desc string, contentType string) map[string]any {
	return map[string]any{
		"description": desc,
		"content": map[string]any{
			contentType: map[string]any{
				"schema": map[string]any{"type": "string"},
			},
		},
	}
}

func pathParam(name, desc string) map[string]any {
	return map[string]any{
		"name":        name,
		"in":          "path",
		"description": desc,
		"required":    true,
		"schema":      map[string]any{"type": "string"},
	}
}

func queryParam(name, desc, typ string) map[string]any {
	return map[string]any{
		"name":        name,
		"in":          "query",
		"description": desc,
		"required":    false,
		"schema":      map[string]any{"type": typ},
	}
}
