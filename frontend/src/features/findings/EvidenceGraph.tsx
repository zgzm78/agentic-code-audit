import { useMemo } from "react";
import { Background, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import dagre from "dagre";
import { Box, Braces, CircleDot, FileCode2, Flag, ShieldAlert } from "lucide-react";
import type { ChainGraph } from "../../components/types";

const WIDTH = 244;
const HEIGHT = 96;

const NODE_ICONS: Record<string, any> = { source: CircleDot, function: Braces, condition: ShieldAlert, guard: ShieldAlert, sink: Flag, effect: Box, artifact: FileCode2 };

function EvidenceNode({ data }: NodeProps) {
  const type = String(data.kind || "function").toLowerCase();
  const Icon = NODE_ICONS[type] || Braces;
  return <div className={`evidence-node node-${type}`}>
    <Handle type="target" position={Position.Top} />
    <div className="node-sequence">{String(data.sequence).padStart(2, "0")}</div>
    <div className="node-icon"><Icon size={18} /></div>
    <div className="node-copy"><div className="node-kind"><i />{type}</div><strong title={String(data.label)}>{String(data.label)}</strong>{data.location && <span title={String(data.fullLocation)}><FileCode2 size={11} />{String(data.location)}</span>}</div>
    <div className="node-corner" />
    <Handle type="source" position={Position.Bottom} />
  </div>;
}

const nodeTypes = { evidence: EvidenceNode };

export default function EvidenceGraph({ graph, onNodeSelect }: { graph?: ChainGraph; onNodeSelect?: (node: any) => void }) {
  const layout = useMemo(() => buildLayout(graph), [graph]);
  if (!graph?.nodes?.length) return <div className="graph-empty"><div className="graph-empty-radar"><span /><i /><b /></div><strong>等待证据链</strong><p>Source、调用路径与危险 Sink 将在这里形成可验证的攻击轨迹。</p></div>;
  return <div className="evidence-canvas"><div className="canvas-scan" /><ReactFlow nodes={layout.nodes} edges={layout.edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: .16, maxZoom: .92 }} minZoom={.4} maxZoom={1.45} onNodeClick={(_, node) => onNodeSelect?.(node.data.original)} proOptions={{ hideAttribution: true }}>
    <Background color="#283540" gap={24} size={1} />
    <Controls showInteractive={false} />
    <MiniMap nodeColor={(node) => node.data.kind === "sink" ? "#ef5b5b" : node.data.kind === "source" ? "#46c4ac" : "#607283"} maskColor="rgba(7, 12, 17, .75)" />
  </ReactFlow></div>;
}

function buildLayout(graph?: ChainGraph): { nodes: Node[]; edges: Edge[] } {
  if (!graph) return { nodes: [], edges: [] };
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "TB", ranksep: 68, nodesep: 46, marginx: 36, marginy: 36 });
  graph.nodes.forEach((node) => g.setNode(node.id, { width: WIDTH, height: HEIGHT }));
  graph.edges.forEach((edge) => g.setEdge(edge.source, edge.target));
  if (!graph.edges.length) graph.nodes.slice(1).forEach((node, i) => g.setEdge(graph.nodes[i].id, node.id));
  dagre.layout(g);
  const nodes = graph.nodes.map((node, index) => { const pos = g.node(node.id); const fullLocation = node.file_path ? `${node.file_path}:${node.line || ""}` : ""; const shortFile = node.file_path?.replace(/\\/g, "/").split("/").slice(-2).join("/") || ""; return { id: node.id, type: "evidence", position: { x: pos.x - WIDTH / 2, y: pos.y - HEIGHT / 2 }, data: { label: node.label, kind: node.type, sequence: index + 1, location: shortFile ? `${shortFile}:${node.line || ""}` : "", fullLocation, original: node } }; });
  const sourceEdges = graph.edges.length ? graph.edges : graph.nodes.slice(1).map((node, i) => ({ source: graph.nodes[i].id, target: node.id, type: "flow", label: "" }));
  const edges = sourceEdges.map((edge, index) => { const relation = String(edge.type || "flow").replace(/_/g, " "); const control = relation.includes("control"); const inferred = relation.includes("inferred"); const color = control ? "#d8b45d" : inferred ? "#718390" : "#52cbb0"; return { id: `${edge.source}-${edge.target}-${index}`, source: edge.source, target: edge.target, type: "smoothstep", animated: !inferred, label: edge.label || relation, labelStyle: { fill: control ? "#e2c878" : "#9bb1bd", fontSize: 11, fontWeight: 600 }, labelBgPadding: [7, 4] as [number, number], labelBgBorderRadius: 2, labelBgStyle: { fill: "#0b1217", fillOpacity: .96, stroke: "#25343e", strokeWidth: 1 }, style: { stroke: color, strokeWidth: 2, strokeDasharray: inferred ? "6 6" : undefined }, markerEnd: { type: MarkerType.ArrowClosed, color, width: 18, height: 18 } }; });
  return { nodes, edges };
}
