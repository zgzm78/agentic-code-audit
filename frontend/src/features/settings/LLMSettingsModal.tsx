import { useEffect, useState } from "react";
import { Bot, CheckCircle2, Eye, EyeOff, LoaderCircle, Save, TestTube2, X, XCircle } from "lucide-react";
import { motion } from "motion/react";
import { api, type LLMSettings, type LLMTestResult } from "../../api/client";

export default function LLMSettingsModal({ onClose }: { onClose: () => void }) {
  const [settings, setSettings] = useState<LLMSettings>({ provider: "openai-compatible", base_url: "", model: "", api_key: "" });
  const [showKey, setShowKey] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<LLMTestResult | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.llmSettings().then((value) => setSettings({ ...value, api_key: "" })).catch((err) => setError(err.message)).finally(() => setLoading(false));
  }, []);

  const payload = (): LLMSettings => ({ provider: settings.provider, base_url: settings.base_url, model: settings.model, api_key: settings.api_key || "" });
  async function test() {
    setTesting(true); setResult(null); setError("");
    try { setResult(await api.testLLMSettings(payload())); } catch (err) { setError((err as Error).message); }
    finally { setTesting(false); }
  }
  async function save() {
    setSaving(true); setError("");
    try { const value = await api.saveLLMSettings(payload()); setSettings({ ...value, api_key: "" }); window.dispatchEvent(new Event("llm-settings-updated")); }
    catch (err) { setError((err as Error).message); }
    finally { setSaving(false); }
  }

  return <div className="modal-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
    <motion.section className="settings-modal" initial={{ opacity: 0, scale: .97, y: 14 }} animate={{ opacity: 1, scale: 1, y: 0 }}>
      <header className="settings-modal-head"><div className="settings-symbol"><Bot size={22} /><span /></div><div><small>MODEL GATEWAY</small><h2>LLM 连接配置</h2><p>配置会安全保存在本机 data 目录，并立即用于下一次审计。</p></div><button onClick={onClose} aria-label="关闭"><X size={19} /></button></header>
      {loading ? <div className="settings-loading"><LoaderCircle className="spin" />读取配置</div> : <div className="settings-form">
        <label><span>兼容协议</span><select value={settings.provider} onChange={(e) => setSettings({ ...settings, provider: e.target.value })}><option value="openai-compatible">OpenAI Compatible</option><option value="deepseek">DeepSeek</option><option value="openai">OpenAI</option></select></label>
        <label><span>Base URL</span><input value={settings.base_url} onChange={(e) => setSettings({ ...settings, base_url: e.target.value })} placeholder="https://api.example.com/v1" /><small>填写到 /v1，不要包含 /chat/completions</small></label>
        <label><span>Model ID</span><input value={settings.model} onChange={(e) => setSettings({ ...settings, model: e.target.value })} placeholder="模型的准确标识" /></label>
        <label><span>API Key</span><div className="secret-input"><input type={showKey ? "text" : "password"} value={settings.api_key || ""} onChange={(e) => setSettings({ ...settings, api_key: e.target.value })} placeholder={settings.api_key_configured ? `已配置 ${settings.api_key_hint}，留空则保持不变` : "输入 API Key"} /><button onClick={() => setShowKey((value) => !value)} type="button">{showKey ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
        <div className="settings-security"><i />API Key 不会返回到浏览器；页面只显示是否已配置及末四位提示。</div>
        {(result || error) && <div className={`connection-result ${result?.ok ? "success" : "failed"}`}>{result?.ok ? <CheckCircle2 size={18} /> : <XCircle size={18} />}<div><strong>{result?.ok ? "连接成功" : "连接失败"}</strong><span>{result?.ok ? `${result.model} · ${result.latency_ms} ms · ${result.message}` : result?.error || error}</span></div></div>}
      </div>}
      <footer className="settings-actions"><button className="settings-test" onClick={test} disabled={loading || testing}>{testing ? <LoaderCircle className="spin" size={16} /> : <TestTube2 size={16} />}测试连接</button><button className="action-primary" onClick={save} disabled={loading || saving}>{saving ? <LoaderCircle className="spin" size={16} /> : <Save size={16} />}保存配置</button></footer>
    </motion.section>
  </div>;
}
