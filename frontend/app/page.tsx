"use client";

import { useEffect, useMemo, useState } from "react";
import { Button, Card, CardBody, Chip, Input, Spinner } from "@heroui/react";

type NodeInfo = {
  tag: string;
  name: string;
  uri: string;
  port?: number;
  last_latency_ms?: number;
  available?: boolean;
  blacklisted?: boolean;
  ip_info?: {
    ip?: string;
    pure_score?: string;
    fraud_score?: string;
    bot_score?: string;
    shared_users?: string;
    ip_attr?: string;
    ip_src?: string;
  };
};

type SubscriptionRow = {
  id: number;
  name: string;
  subscription_url: string;
  enabled_update: boolean;
  interval_seconds: number;
  last_node_count: number;
  last_error?: string;
};

type NodeEvent = {
  id: number;
  uri: string;
  event_type: string;
  event_source: string;
  success: boolean;
  latency_ms: number;
  event_at: string;
  error_message?: string;
  ip_port_key?: string;
};

type CurrentNodeRow = {
  id: number;
  name: string;
  uri: string;
  listen_port?: number;
  ip?: string;
  latency_ms: number;
  health_score: number;
  pure_score?: string;
  fraud_score?: string;
  bot_score?: string;
  shared_users?: string;
  ip_type?: string;
  native_ip?: string;
  first_seen_at?: string;
  last_updated_at?: string;
};

type SelectOption = {
  value: string;
  label: string;
};

type CountryOption = {
  value: string;
  label: string;
  iso_code: string;
  count: number;
};

type RegionOption = {
  value: string;
  label: string;
  country: string;
  country_iso: string;
  count: number;
};

type GatewayOption = {
  id: string;
  host: string;
  port: number;
  node_name?: string;
  country?: string;
  country_iso?: string;
  region?: string;
  ip?: string;
  latency_ms: number;
};

type ExtractorOptions = {
  countries: CountryOption[];
  regions: RegionOption[];
  gateways: GatewayOption[];
  protocols: SelectOption[];
  rotation_modes: SelectOption[];
  security_modes: SelectOption[];
  username_templates: SelectOption[];
  password_templates: SelectOption[];
  output_templates: SelectOption[];
  delimiter_options: SelectOption[];
  api_formats: SelectOption[];
  defaults?: Partial<ExtractorForm>;
};

type ExtractorForm = {
  country: string;
  country_iso: string;
  region: string;
  gateway: string;
  protocol: string;
  rotation_mode: string;
  rotation_seconds: number;
  security_mode: string;
  user_id: string;
  username: string;
  password: string;
  username_template: string;
  password_template: string;
  output_template: string;
  delimiter: string;
  custom_delimiter: string;
  api_response_format: string;
  limit: number;
};

type ExtractorGenerateResponse = {
  count: number;
  content: string;
  csv?: string;
};

type ExtractorLinkResponse = {
  fetch_url: string;
  signed_short_url?: string;
  signed_short_code?: string;
  signed_short_expires?: string;
  preview_count: number;
};

const apiBase = process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") || "http://localhost:9090";
const tokenKey = "easy_proxies_token";

const defaultExtractorForm: ExtractorForm = {
  country: "",
  country_iso: "",
  region: "",
  gateway: "",
  protocol: "http",
  rotation_mode: "sticky",
  rotation_seconds: 300,
  security_mode: "account_password",
  user_id: "10001",
  username: "proxyuser",
  password: "proxypass",
  username_template: "uid_username",
  password_template: "password_plain",
  output_template: "user_pass_at_gateway",
  delimiter: "newline",
  custom_delimiter: "",
  api_response_format: "txt",
  limit: 0
};

function applyExtractorDefaults(current: ExtractorForm, defaults?: Partial<ExtractorForm>): ExtractorForm {
  if (!defaults) return current;
  return {
    ...current,
    protocol: current.protocol || defaults.protocol || defaultExtractorForm.protocol,
    rotation_mode: current.rotation_mode || defaults.rotation_mode || defaultExtractorForm.rotation_mode,
    rotation_seconds: current.rotation_seconds || defaults.rotation_seconds || defaultExtractorForm.rotation_seconds,
    security_mode: current.security_mode || defaults.security_mode || defaultExtractorForm.security_mode,
    username_template: current.username_template || defaults.username_template || defaultExtractorForm.username_template,
    password_template: current.password_template || defaults.password_template || defaultExtractorForm.password_template,
    output_template: current.output_template || defaults.output_template || defaultExtractorForm.output_template,
    delimiter: current.delimiter || defaults.delimiter || defaultExtractorForm.delimiter,
    api_response_format: current.api_response_format || defaults.api_response_format || defaultExtractorForm.api_response_format
  };
}

function displayBotScore(row: CurrentNodeRow): string {
  const botScore = row.bot_score?.trim();
  if (botScore) return botScore;
  if (row.fraud_score?.trim() || row.pure_score?.trim() || row.ip?.trim()) {
    return "源站未返回";
  }
  return "-";
}

export default function Home() {
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [currentNodes, setCurrentNodes] = useState<CurrentNodeRow[]>([]);
  const [subscriptions, setSubscriptions] = useState<SubscriptionRow[]>([]);
  const [events, setEvents] = useState<NodeEvent[]>([]);

  const [extractorOptions, setExtractorOptions] = useState<ExtractorOptions | null>(null);
  const [extractorForm, setExtractorForm] = useState<ExtractorForm>(defaultExtractorForm);
  const [extractorBusy, setExtractorBusy] = useState(false);
  const [extractorError, setExtractorError] = useState("");
  const [extractorNotice, setExtractorNotice] = useState("");
  const [extractorOutput, setExtractorOutput] = useState("");
  const [extractorCSV, setExtractorCSV] = useState("");
  const [extractorLink, setExtractorLink] = useState("");
  const [extractorCount, setExtractorCount] = useState(0);

  const healthyCount = useMemo(() => nodes.filter((n) => n.available && !n.blacklisted).length, [nodes]);

  const filteredRegions = useMemo(() => {
    if (!extractorOptions?.regions?.length) return [];
    if (!extractorForm.country && !extractorForm.country_iso) return extractorOptions.regions;
    return extractorOptions.regions.filter((item) => {
      if (extractorForm.country && item.country === extractorForm.country) return true;
      if (extractorForm.country_iso && item.country_iso === extractorForm.country_iso) return true;
      return false;
    });
  }, [extractorOptions, extractorForm.country, extractorForm.country_iso]);

  const filteredGateways = useMemo(() => {
    if (!extractorOptions?.gateways?.length) return [];
    return extractorOptions.gateways.filter((gw) => {
      if (extractorForm.country && gw.country && gw.country !== extractorForm.country) {
        return false;
      }
      if (extractorForm.country_iso && gw.country_iso && gw.country_iso !== extractorForm.country_iso) {
        return false;
      }
      if (extractorForm.region && gw.region && gw.region !== extractorForm.region) {
        return false;
      }
      return true;
    });
  }, [extractorOptions, extractorForm.country, extractorForm.country_iso, extractorForm.region]);

  useEffect(() => {
    const saved = window.localStorage.getItem(tokenKey) || "";
    if (!saved) return;
    setToken(saved);
    void loadData(saved);
  }, []);

  async function authHeaders(authToken: string) {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${authToken}`
    };
  }

  async function loadData(authToken: string) {
    setLoading(true);
    setError("");
    try {
      const [nodesRes, currentNodesRes, subsRes, eventsRes, extractorOptionsRes] = await Promise.all([
        fetch(`${apiBase}/api/nodes`, { headers: await authHeaders(authToken), cache: "no-store" }),
        fetch(`${apiBase}/api/nodes/current`, { headers: await authHeaders(authToken), cache: "no-store" }),
        fetch(`${apiBase}/api/subscriptions`, { headers: await authHeaders(authToken), cache: "no-store" }),
        fetch(`${apiBase}/api/nodes/events?limit=120`, { headers: await authHeaders(authToken), cache: "no-store" }),
        fetch(`${apiBase}/api/extractor/options`, { headers: await authHeaders(authToken), cache: "no-store" })
      ]);

      if (
        nodesRes.status === 401 ||
        currentNodesRes.status === 401 ||
        subsRes.status === 401 ||
        eventsRes.status === 401 ||
        extractorOptionsRes.status === 401
      ) {
        setToken("");
        window.localStorage.removeItem(tokenKey);
        setError("登录已过期，请重新输入密码。");
        return;
      }

      const nodesJson = await nodesRes.json();
      const currentNodesJson = await currentNodesRes.json();
      const subsJson = await subsRes.json();
      const eventsJson = await eventsRes.json();
      const optionsJson = (await extractorOptionsRes.json()) as ExtractorOptions;

      setNodes((nodesJson.all_nodes || nodesJson.nodes || []) as NodeInfo[]);
      setCurrentNodes((currentNodesJson.nodes || []) as CurrentNodeRow[]);
      setSubscriptions((subsJson.subscriptions || []) as SubscriptionRow[]);
      setEvents((eventsJson.events || []) as NodeEvent[]);
      setExtractorOptions(optionsJson);
      setExtractorForm((prev) => applyExtractorDefaults(prev, optionsJson.defaults));
    } catch (e) {
      setError(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  async function login() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${apiBase}/api/auth`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
      });
      const data = await res.json();
      if (!res.ok || !data.token) {
        setError(data.error || "登录失败");
        return;
      }
      setToken(data.token);
      window.localStorage.setItem(tokenKey, data.token);
      await loadData(data.token);
    } catch (e) {
      setError(e instanceof Error ? e.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  function logout() {
    setToken("");
    setNodes([]);
    setCurrentNodes([]);
    setSubscriptions([]);
    setEvents([]);
    setExtractorOptions(null);
    setExtractorOutput("");
    setExtractorCSV("");
    setExtractorLink("");
    window.localStorage.removeItem(tokenKey);
  }

  function updateExtractor<K extends keyof ExtractorForm>(key: K, value: ExtractorForm[K]) {
    setExtractorForm((prev) => ({ ...prev, [key]: value }));
  }

  async function generateConnections() {
    if (!token) return;
    setExtractorBusy(true);
    setExtractorError("");
    setExtractorNotice("");
    try {
      const res = await fetch(`${apiBase}/api/extractor/generate`, {
        method: "POST",
        headers: await authHeaders(token),
        body: JSON.stringify(extractorForm)
      });
      const data = (await res.json()) as ExtractorGenerateResponse & { error?: string };
      if (!res.ok) {
        setExtractorError(data.error || "生成失败");
        return;
      }
      setExtractorOutput(data.content || "");
      setExtractorCSV(data.csv || "");
      setExtractorCount(data.count || 0);
      setExtractorLink("");
      setExtractorNotice(`已生成 ${data.count || 0} 条连接`);
    } catch (e) {
      setExtractorError(e instanceof Error ? e.message : "生成失败");
    } finally {
      setExtractorBusy(false);
    }
  }

  async function generateAPIExtractLink() {
    if (!token) return;
    setExtractorBusy(true);
    setExtractorError("");
    setExtractorNotice("");
    try {
      const res = await fetch(`${apiBase}/api/extractor/link`, {
        method: "POST",
        headers: await authHeaders(token),
        body: JSON.stringify(extractorForm)
      });
      const data = (await res.json()) as ExtractorLinkResponse & { error?: string };
      if (!res.ok) {
        setExtractorError(data.error || "生成链接失败");
        return;
      }
      const finalLink = data.signed_short_url || data.fetch_url || "";
      setExtractorLink(finalLink);
      setExtractorCount(data.preview_count || 0);
      const expiresText = data.signed_short_expires
        ? `，有效期至 ${new Date(data.signed_short_expires).toLocaleString()}`
        : "";
      setExtractorNotice(`API 链接已生成（预览 ${data.preview_count || 0} 条）${expiresText}`);
    } catch (e) {
      setExtractorError(e instanceof Error ? e.message : "生成链接失败");
    } finally {
      setExtractorBusy(false);
    }
  }

  async function copyText(content: string, message: string) {
    if (!content) return;
    setExtractorError("");
    try {
      await navigator.clipboard.writeText(content);
      setExtractorNotice(message);
    } catch {
      setExtractorError("复制失败，请手动复制");
    }
  }

  function selectCountry(countryName: string) {
    const hit = extractorOptions?.countries?.find((item) => item.value === countryName);
    setExtractorForm((prev) => ({
      ...prev,
      country: countryName,
      country_iso: hit?.iso_code || "",
      region: "",
      gateway: ""
    }));
  }

  function selectRegion(regionName: string) {
    setExtractorForm((prev) => ({
      ...prev,
      region: regionName,
      gateway: ""
    }));
  }

  if (!token) {
    return (
      <main className="login-wrap">
        <Card className="login-card">
          <CardBody>
            <h1>Easy Proxies 管理台</h1>
            <p>输入后台 `management.password` 后进入。</p>
            <Input
              type="password"
              label="访问密码"
              value={password}
              onValueChange={setPassword}
              variant="bordered"
            />
            <Button color="primary" onPress={login} isDisabled={!password || loading}>
              {loading ? <Spinner size="sm" color="current" /> : "登录"}
            </Button>
            {error ? <div className="error-box">{error}</div> : null}
          </CardBody>
        </Card>
      </main>
    );
  }

  return (
    <main className="dashboard-wrap">
      <header className="topbar">
        <div>
          <h1>Easy Proxies SQLite 控制台</h1>
          <p>前后端分离 · HeroUI Pro 风格管理界面</p>
        </div>
        <div className="toolbar">
          <Button color="secondary" variant="flat" onPress={() => void loadData(token)} isDisabled={loading}>
            刷新
          </Button>
          <Button color="danger" variant="light" onPress={logout}>
            退出
          </Button>
        </div>
      </header>

      {error ? <div className="error-box">{error}</div> : null}

      <section className="metrics-grid">
        <Card>
          <CardBody>
            <h3>当前节点</h3>
            <strong>{currentNodes.length || nodes.length}</strong>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <h3>健康节点</h3>
            <strong>{healthyCount}</strong>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <h3>订阅来源</h3>
            <strong>{subscriptions.length}</strong>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <h3>最近流水</h3>
            <strong>{events.length}</strong>
          </CardBody>
        </Card>
      </section>

      <section className="panel extractor-panel">
        <div className="panel-head">
          <h2>账号密码认证提取</h2>
          <div className="extractor-head-actions">
            <Chip color="primary" variant="flat">
              输出 {extractorCount} 条
            </Chip>
          </div>
        </div>

        <div className="extractor-grid">
          <label>
            <span>1. 可用国家</span>
            <select value={extractorForm.country} onChange={(e) => selectCountry(e.target.value)}>
              <option value="">全部国家</option>
              {(extractorOptions?.countries || []).map((item) => (
                <option key={`${item.value}-${item.iso_code}`} value={item.value}>
                  {item.label} · {item.count}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>2. 可选地区</span>
            <select value={extractorForm.region} onChange={(e) => selectRegion(e.target.value)}>
              <option value="">全部地区</option>
              {filteredRegions.map((item) => (
                <option key={`${item.country_iso}-${item.value}`} value={item.value}>
                  {item.label} · {item.count}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>3. 网关节点</span>
            <select value={extractorForm.gateway} onChange={(e) => updateExtractor("gateway", e.target.value)}>
              <option value="">自动匹配网关</option>
              {filteredGateways.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.id}
                  {item.node_name ? ` · ${item.node_name}` : ""}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>4. 代理协议</span>
            <select value={extractorForm.protocol} onChange={(e) => updateExtractor("protocol", e.target.value)}>
              {(extractorOptions?.protocols || []).map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>5. IP轮转策略</span>
            <select value={extractorForm.rotation_mode} onChange={(e) => updateExtractor("rotation_mode", e.target.value)}>
              {(extractorOptions?.rotation_modes || []).map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>轮转间隔(秒)</span>
            <input
              type="number"
              min={1}
              value={extractorForm.rotation_seconds}
              disabled={extractorForm.rotation_mode !== "timed"}
              onChange={(e) => updateExtractor("rotation_seconds", Number(e.target.value || 0))}
            />
          </label>

          <label>
            <span>6. 安全策略</span>
            <select value={extractorForm.security_mode} onChange={(e) => updateExtractor("security_mode", e.target.value)}>
              {(extractorOptions?.security_modes || []).map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>用户ID</span>
            <input value={extractorForm.user_id} onChange={(e) => updateExtractor("user_id", e.target.value)} />
          </label>

          <label>
            <span>用户名</span>
            <input value={extractorForm.username} onChange={(e) => updateExtractor("username", e.target.value)} />
          </label>

          <label>
            <span>密码</span>
            <input value={extractorForm.password} onChange={(e) => updateExtractor("password", e.target.value)} />
          </label>

          <label>
            <span>7. 线路连接用户名模板</span>
            <select value={extractorForm.username_template} onChange={(e) => updateExtractor("username_template", e.target.value)}>
              {(extractorOptions?.username_templates || []).map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>8. 线路连接密码模板</span>
            <select value={extractorForm.password_template} onChange={(e) => updateExtractor("password_template", e.target.value)}>
              {(extractorOptions?.password_templates || []).map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>9. 生成格式</span>
            <select value={extractorForm.output_template} onChange={(e) => updateExtractor("output_template", e.target.value)}>
              {(extractorOptions?.output_templates || []).map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>10. 分隔符</span>
            <select value={extractorForm.delimiter} onChange={(e) => updateExtractor("delimiter", e.target.value)}>
              {(extractorOptions?.delimiter_options || []).map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>自定义分隔符</span>
            <input
              value={extractorForm.custom_delimiter}
              disabled={extractorForm.delimiter !== "custom"}
              onChange={(e) => updateExtractor("custom_delimiter", e.target.value)}
              placeholder="如 | 或 \\n"
            />
          </label>

          <label>
            <span>API返回格式</span>
            <select value={extractorForm.api_response_format} onChange={(e) => updateExtractor("api_response_format", e.target.value)}>
              {(extractorOptions?.api_formats || []).map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>生成数量限制(0=全部)</span>
            <input
              type="number"
              min={0}
              value={extractorForm.limit}
              onChange={(e) => updateExtractor("limit", Number(e.target.value || 0))}
            />
          </label>
        </div>

        <div className="extractor-actions">
          <Button color="primary" onPress={() => void generateConnections()} isDisabled={extractorBusy}>
            {extractorBusy ? <Spinner size="sm" color="current" /> : "生成连接信息"}
          </Button>
          <Button color="secondary" onPress={() => void generateAPIExtractLink()} isDisabled={extractorBusy}>
            生成API提取链接
          </Button>
          <Button variant="flat" onPress={() => void copyText(extractorOutput, "连接信息已复制")} isDisabled={!extractorOutput}>
            复制连接信息
          </Button>
          <Button variant="flat" onPress={() => void copyText(extractorLink, "API链接已复制")} isDisabled={!extractorLink}>
            复制API链接
          </Button>
        </div>

        {extractorError ? <div className="error-box">{extractorError}</div> : null}
        {extractorNotice ? <div className="notice-box">{extractorNotice}</div> : null}

        {extractorLink ? (
          <div className="result-box">
            <h3>API 提取链接</h3>
            <p className="mono link-text">{extractorLink}</p>
          </div>
        ) : null}

        {extractorOutput ? (
          <div className="result-box">
            <h3>连接信息输出</h3>
            <textarea value={extractorOutput} readOnly rows={8} className="mono result-textarea" />
          </div>
        ) : null}

        {extractorCSV ? (
          <details className="result-box">
            <summary>CSV 预览</summary>
            <textarea value={extractorCSV} readOnly rows={8} className="mono result-textarea" />
          </details>
        ) : null}
      </section>

      <section className="panel">
        <h2>订阅表 (table1)</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>名称</th>
                <th>URL</th>
                <th>自动更新</th>
                <th>间隔(s)</th>
                <th>最近节点数</th>
                <th>错误</th>
              </tr>
            </thead>
            <tbody>
              {subscriptions.map((sub) => (
                <tr key={sub.id}>
                  <td>{sub.name}</td>
                  <td className="mono">{sub.subscription_url}</td>
                  <td>{sub.enabled_update ? "是" : "否"}</td>
                  <td>{sub.interval_seconds}</td>
                  <td>{sub.last_node_count}</td>
                  <td>{sub.last_error || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h2>当前节点表 (table2)</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>名称</th>
                <th>端口</th>
                <th>IP</th>
                <th>延迟</th>
                <th>健康度</th>
                <th>纯净度</th>
                <th>Fraud</th>
                <th>Bot</th>
                <th>共享</th>
                <th>IP类型</th>
                <th>原生IP</th>
                <th>入库时间</th>
                <th>最后更新时间</th>
              </tr>
            </thead>
            <tbody>
              {currentNodes.map((n) => (
                <tr key={n.id || n.uri}>
                  <td>{n.name}</td>
                  <td>{n.listen_port || "-"}</td>
                  <td className="mono">{n.ip || "-"}</td>
                  <td>{n.latency_ms >= 0 ? `${n.latency_ms}ms` : "-"}</td>
                  <td>{n.health_score >= 0 ? n.health_score.toFixed(1) : "-"}</td>
                  <td>{n.pure_score || "-"}</td>
                  <td>{n.fraud_score || "-"}</td>
                  <td>{displayBotScore(n)}</td>
                  <td>{n.shared_users || "-"}</td>
                  <td>{n.ip_type || "-"}</td>
                  <td>{n.native_ip || "-"}</td>
                  <td>{n.first_seen_at ? new Date(n.first_seen_at).toLocaleString() : "-"}</td>
                  <td>{n.last_updated_at ? new Date(n.last_updated_at).toLocaleString() : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h2>流水表 (table3)</h2>
        <div className="events-grid">
          {events.map((ev) => (
            <Card key={ev.id} className="event-card">
              <CardBody>
                <div className="event-head">
                  <Chip color={ev.success ? "success" : "danger"} variant="flat">
                    {ev.event_type}
                  </Chip>
                  <span>{new Date(ev.event_at).toLocaleString()}</span>
                </div>
                <p className="mono">{ev.uri}</p>
                <p>
                  source: <strong>{ev.event_source || "-"}</strong>
                </p>
                <p>
                  latency: <strong>{ev.latency_ms >= 0 ? `${ev.latency_ms}ms` : "-"}</strong>
                </p>
                <p>{ev.error_message || "OK"}</p>
              </CardBody>
            </Card>
          ))}
        </div>
      </section>
    </main>
  );
}
