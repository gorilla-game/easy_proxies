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
						"region":             map[string]any{"type": "string"},
						"country":            map[string]any{"type": "string"},
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
						"all_nodes": map[string]any{
							"type":  "array",
							"items": schemaRef("NodeSnapshot"),
						},
						"total_nodes": map[string]any{"type": "integer"},
						"region_stats": map[string]any{
							"type":                 "object",
							"additionalProperties": map[string]any{"type": "integer"},
						},
						"region_healthy": map[string]any{
							"type":                 "object",
							"additionalProperties": map[string]any{"type": "integer"},
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
				"ExtractorGenerateRequest": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"country":             map[string]any{"type": "string"},
						"country_iso":         map[string]any{"type": "string"},
						"region":              map[string]any{"type": "string"},
						"gateway":             map[string]any{"type": "string"},
						"protocol":            map[string]any{"type": "string"},
						"rotation_mode":       map[string]any{"type": "string"},
						"rotation_seconds":    map[string]any{"type": "integer"},
						"security_mode":       map[string]any{"type": "string"},
						"user_id":             map[string]any{"type": "string"},
						"username":            map[string]any{"type": "string"},
						"password":            map[string]any{"type": "string"},
						"username_template":   map[string]any{"type": "string"},
						"password_template":   map[string]any{"type": "string"},
						"output_template":     map[string]any{"type": "string"},
						"delimiter":           map[string]any{"type": "string"},
						"custom_delimiter":    map[string]any{"type": "string"},
						"api_response_format": map[string]any{"type": "string"},
						"limit":               map[string]any{"type": "integer"},
					},
				},
				"ExtractorGenerateResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"count":       map[string]any{"type": "integer"},
						"content":     map[string]any{"type": "string"},
						"connections": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						"entries":     map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
					},
				},
				"ExtractorLinkResponse": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"fetch_url":            map[string]any{"type": "string"},
						"signed_short_url":     map[string]any{"type": "string"},
						"signed_short_code":    map[string]any{"type": "string"},
						"signed_short_expires": map[string]any{"type": "string", "format": "date-time"},
						"api_response_format":  map[string]any{"type": "string"},
						"preview_count":        map[string]any{"type": "integer"},
						"preview_first_line":   map[string]any{"type": "string"},
						"has_token_in_query":   map[string]any{"type": "boolean"},
					},
				},
			},
		},
		"paths": map[string]any{
			"/api/auth": map[string]any{
				"get": map[string]any{
					"summary":   "Get auth status",
					"responses": map[string]any{"200": map[string]any{"description": "Auth status", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("AuthResponse")}}}},
				},
				"post": map[string]any{
					"summary":     "Login",
					"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("AuthRequest")}}},
					"responses":   map[string]any{"200": map[string]any{"description": "Login success", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("AuthResponse")}}}},
				},
			},
			"/api/nodes": map[string]any{
				"get": map[string]any{
					"summary":   "List nodes",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Node list", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("NodeListResponse")}}}},
				},
			},
			"/api/nodes/current": map[string]any{
				"get": map[string]any{
					"summary":   "List current sqlite nodes",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Current nodes"}},
				},
			},
			"/api/nodes/events": map[string]any{
				"get": map[string]any{
					"summary":   "List node events",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Node events"}},
				},
			},
			"/api/extractor/options": map[string]any{
				"get": map[string]any{
					"summary":   "Extractor option lists",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Extractor options"}},
				},
			},
			"/api/extractor/generate": map[string]any{
				"post": map[string]any{
					"summary":     "Generate account/password connection lines",
					"security":    []map[string]any{{"bearerAuth": []string{}}},
					"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("ExtractorGenerateRequest")}}},
					"responses":   map[string]any{"200": map[string]any{"description": "Extractor result", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("ExtractorGenerateResponse")}}}},
				},
			},
			"/api/extractor/link": map[string]any{
				"post": map[string]any{
					"summary":     "Generate extractor API fetch link",
					"security":    []map[string]any{{"bearerAuth": []string{}}},
					"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("ExtractorGenerateRequest")}}},
					"responses":   map[string]any{"200": map[string]any{"description": "Extractor link", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("ExtractorLinkResponse")}}}},
				},
			},
			"/api/extractor/fetch": map[string]any{
				"get": map[string]any{
					"summary": "Fetch generated extractor data (txt/csv/json)",
					"parameters": []map[string]any{
						{"name": "sl", "in": "query", "required": false, "schema": map[string]any{"type": "string"}, "description": "Signed short link code"},
						{"name": "payload", "in": "query", "required": false, "schema": map[string]any{"type": "string"}, "description": "Legacy payload token"},
						{"name": "format", "in": "query", "required": false, "schema": map[string]any{"type": "string"}},
						{"name": "token", "in": "query", "required": false, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{"200": map[string]any{"description": "Extractor fetch output"}},
				},
			},
			"/api/subscriptions": map[string]any{
				"get": map[string]any{
					"summary":   "List subscriptions",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Subscriptions"}},
				},
				"post": map[string]any{
					"summary":     "Add subscription",
					"security":    []map[string]any{{"bearerAuth": []string{}}},
					"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "properties": map[string]any{"subscription_url": map[string]any{"type": "string"}}}}}},
					"responses":   map[string]any{"200": map[string]any{"description": "Added", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
				"delete": map[string]any{
					"summary":     "Delete subscription",
					"security":    []map[string]any{{"bearerAuth": []string{}}},
					"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object", "properties": map[string]any{"subscription_url": map[string]any{"type": "string"}}}}}},
					"responses":   map[string]any{"200": map[string]any{"description": "Deleted", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
			},
			"/api/settings": map[string]any{
				"get": map[string]any{
					"summary":   "Get settings",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Settings", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("SettingsResponse")}}}},
				},
				"put": map[string]any{
					"summary":     "Update settings",
					"security":    []map[string]any{{"bearerAuth": []string{}}},
					"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("SettingsUpdate")}}},
					"responses":   map[string]any{"200": map[string]any{"description": "Updated", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
			},
			"/api/nodes/{tag}/probe": map[string]any{
				"post": map[string]any{
					"summary":    "Probe node",
					"security":   []map[string]any{{"bearerAuth": []string{}}},
					"parameters": []map[string]any{{"name": "tag", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}},
					"responses":  map[string]any{"200": map[string]any{"description": "Probe result", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("ProbeResponse")}}}},
				},
			},
			"/api/nodes/{tag}/release": map[string]any{
				"post": map[string]any{
					"summary":    "Release node",
					"security":   []map[string]any{{"bearerAuth": []string{}}},
					"parameters": []map[string]any{{"name": "tag", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}},
					"responses":  map[string]any{"200": map[string]any{"description": "Released", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
			},
			"/api/nodes/probe-all": map[string]any{
				"post": map[string]any{
					"summary":   "Probe all nodes",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "SSE stream"}},
				},
			},
			"/api/export": map[string]any{
				"get": map[string]any{
					"summary":   "Export proxies",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Export result", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("ExportResponse")}}}},
				},
			},
			"/api/export/filter": map[string]any{
				"get": map[string]any{
					"summary":   "Export filtered proxies",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Export result", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("ExportFilterResponse")}}}},
				},
			},
			"/api/subscription/status": map[string]any{
				"get": map[string]any{
					"summary":   "Subscription status",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Status", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("SubscriptionStatus")}}}},
				},
			},
			"/api/subscription/refresh": map[string]any{
				"post": map[string]any{
					"summary":   "Refresh subscription",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Refreshed", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
			},
			"/api/debug": map[string]any{
				"get": map[string]any{
					"summary":   "Debug info",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Debug info"}},
				},
			},
			"/api/nodes/config": map[string]any{
				"get": map[string]any{
					"summary":   "List config nodes",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Node list", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("ConfigNodesResponse")}}}},
				},
				"post": map[string]any{
					"summary":     "Create config node",
					"security":    []map[string]any{{"bearerAuth": []string{}}},
					"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("NodeConfig")}}},
					"responses":   map[string]any{"200": map[string]any{"description": "Created", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
				"delete": map[string]any{
					"summary":   "Delete all config nodes",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Deleted", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
			},
			"/api/nodes/config/{name}": map[string]any{
				"put": map[string]any{
					"summary":     "Update config node",
					"security":    []map[string]any{{"bearerAuth": []string{}}},
					"parameters":  []map[string]any{{"name": "name", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}},
					"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("NodeConfig")}}},
					"responses":   map[string]any{"200": map[string]any{"description": "Updated", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
				"delete": map[string]any{
					"summary":    "Delete config node",
					"security":   []map[string]any{{"bearerAuth": []string{}}},
					"parameters": []map[string]any{{"name": "name", "in": "path", "required": true, "schema": map[string]any{"type": "string"}}},
					"responses":  map[string]any{"200": map[string]any{"description": "Deleted", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
			},
			"/api/reload": map[string]any{
				"post": map[string]any{
					"summary":   "Reload config",
					"security":  []map[string]any{{"bearerAuth": []string{}}},
					"responses": map[string]any{"200": map[string]any{"description": "Reloaded", "content": map[string]any{"application/json": map[string]any{"schema": schemaRef("MessageResponse")}}}},
				},
			},
		},
	}
}

func schemaRef(name string) map[string]any {
	return map[string]any{
		"$ref": "#/components/schemas/" + name,
	}
}
