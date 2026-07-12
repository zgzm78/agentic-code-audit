import { useMemo } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Download, FileJson, FileText, ShieldCheck } from "lucide-react";
import type { AuditData } from "../../App";
import { API_BASE } from "../../api/client";

export default function ReportView({ data }: { data: AuditData }) {
  const critical = data.findings.filter((f) => f.severity === "critical").length;
  const high = data.findings.filter((f) => f.severity === "high").length;
  const verified = data.findings.filter((f) => ["verified", "exploitable"].includes(String(f.verification?.status))).length;
  const headings = useMemo(() => extractHeadings(data.report), [data.report]);
  return <div className="view report-view">
    <section className="view-intro"><div><span className="eyebrow">AUDIT REPORT</span><h1>审计结论</h1><p>结构化呈现风险、证据、验证结果与修复建议。</p></div><div className="report-actions"><a href={data.task ? `${API_BASE}/api/tasks/${data.task.id}/report.md` : "#"} target="_blank"><FileText size={15} />Markdown</a><a href={data.task ? `${API_BASE}/api/tasks/${data.task.id}/report.json` : "#"} target="_blank"><FileJson size={15} />JSON</a><a href={data.task ? `${API_BASE}/api/tasks/${data.task.id}/mining-debug.json` : "#"} target="_blank"><Download size={15} />调试数据</a></div></section>
    <section className="report-masthead"><div className="report-seal"><ShieldCheck size={28} /><i /></div><div><small>AGENTIC CODE AUDIT · EVIDENCE REPORT</small><h2>{data.task?.target || "未选择审计目标"}</h2><p>生成时间 {data.task?.finished_at ? new Date(data.task.finished_at).toLocaleString("zh-CN") : "等待任务完成"}</p></div><div className="report-score"><small>风险指数</small><strong>{Math.min(100, critical * 25 + high * 12 + data.findings.length * 3)}</strong><span>/100</span></div></section>
    <section className="report-kpis"><div><small>漏洞发现</small><strong>{data.findings.length}</strong></div><div><small>高危及以上</small><strong>{critical + high}</strong></div><div><small>验证通过</small><strong>{verified}</strong></div><div><small>证据节点</small><strong>{data.findings.reduce((n, f) => n + (f.chain_graph?.nodes?.length || 0), 0)}</strong></div></section>
    <section className="report-layout"><aside className="report-outline"><span className="eyebrow">REPORT INDEX</span>{headings.length ? headings.slice(0, 16).map((heading) => <a key={`${heading.id}-${heading.label}`} href={`#${heading.id}`} className={`depth-${heading.depth}`}>{heading.label}</a>) : <span className="outline-empty">报告生成后显示章节目录</span>}</aside><article className="report-paper" id="raw">{data.report ? <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml components={{
      h1: ({ children }) => <h1 id={slugify(textOf(children))}>{children}</h1>,
      h2: ({ children }) => <h2 id={slugify(textOf(children))}>{children}</h2>,
      h3: ({ children }) => <h3 id={slugify(textOf(children))}>{children}</h3>,
      a: ({ href, children }) => <a href={href} target={href?.startsWith("http") ? "_blank" : undefined} rel="noreferrer">{children}</a>,
    }}>{data.report}</ReactMarkdown> : <div className="report-placeholder"><FileText size={38} /><h3>报告尚未生成</h3><p>任务完成后，报告会以结构化阅读模式呈现。</p></div>}</article></section>
  </div>;
}

function extractHeadings(markdown: string) {
  const seen = new Map<string, number>();
  return markdown.split("\n").flatMap((line) => {
    const match = /^(#{1,3})\s+(.+?)\s*$/.exec(line);
    if (!match) return [];
    const label = match[2].replace(/[*_`]/g, "").trim();
    const base = slugify(label);
    const count = seen.get(base) || 0;
    seen.set(base, count + 1);
    return [{ depth: match[1].length, label, id: count ? `${base}-${count + 1}` : base }];
  });
}

function textOf(value: unknown): string {
  if (Array.isArray(value)) return value.map(textOf).join("");
  return String(value ?? "");
}

function slugify(value: string) {
  return value.toLowerCase().trim().replace(/[^\p{L}\p{N}]+/gu, "-").replace(/^-|-$/g, "") || "section";
}
