import { useEffect, useRef, useState } from "react";
import type { PointerEvent } from "react";
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from "d3-force";
import type { Simulation, SimulationNodeDatum, SimulationLinkDatum } from "d3-force";
import { Minus, Pause, Play, Plus, RotateCcw, SlidersHorizontal } from "lucide-react";
import { t } from "../lib/i18n";
import type { AttackGraphFilter, AttackGraphModel, AttackGraphNode, AttackGraphNodeId } from "../lib/attackGraph";
import { filterNode } from "../lib/attackGraph";
import { wheelZoomDelta, zoomCameraAt } from "../lib/graphViewport";

type Point = { x: number; y: number };
type Particle = SimulationNodeDatum & { id: AttackGraphNodeId; radius: number };
type Link = SimulationLinkDatum<Particle> & { id: string };
interface Props { graph: AttackGraphModel; selected: AttackGraphNodeId | null; filter: AttackGraphFilter; onSelect: (id: AttackGraphNodeId) => void; onClear: () => void; onReset: () => void; active: boolean; resetKey: string; }
export function graphMetricLabel(value: string): string {
  const parts = value.match(/^(\d+) (matches|tools|URLs|checks|hits|screenshots|findings|signals)$/);
  return parts ? t(`{count} ${parts[2]}`, { count: parts[1] }) : value;
}
export function graphNodeLabel(node: AttackGraphNode, short = false): string {
  if (node.cluster) {
    const label = t(node.cluster.kind === "findings" ? "{count} more findings" : "{count} discovery URLs", { count: node.cluster.count });
    return short ? label : `${node.cluster.source} · ${label}`;
  }
  const label = short ? node.shortLabel : node.label;
  return node.id.startsWith("finding:") || node.id.startsWith("endpoint:") ? label : t(label);
}
const initialCamera = { x: 0, y: 0, zoom: 1 };
export default function EvidenceGraph({ graph, selected, filter, onSelect, onClear, onReset, active, resetKey }: Props): JSX.Element {
  const svg = useRef<SVGSVGElement>(null);
  const simulation = useRef<Simulation<Particle, Link>>();
  const particles = useRef(new Map<string, Particle>());
  const [camera, setCamera] = useState(initialCamera);
  const [motion, setMotion] = useState(true);
  const [visible, setVisible] = useState(document.visibilityState !== "hidden");
  const [reduced, setReduced] = useState(matchMedia("(prefers-reduced-motion: reduce)").matches);
  const [settings, setSettings] = useState(false);
  const [repulsion, setRepulsion] = useState(90);
  const [distance, setDistance] = useState(55);
  const [zoomSensitivity, setZoomSensitivity] = useState(100);
  const [labels, setLabels] = useState(false);
  const [query, setQuery] = useState("");
  const [hover, setHover] = useState<string | null>(null);
  const [reset, setReset] = useState(0);
  const drag = useRef<{ pointerId: number; id: AttackGraphNodeId | null; client: Point; point: Point; camera: typeof camera; node: Particle | null; origin: Point; fixed: { x: Particle["fx"]; y: Particle["fy"] } } | null>(null);
  const moved = useRef(false);
  const clearSelection = () => { setHover(null); onClear(); };
  const animate = motion && active && visible && !reduced;
  useEffect(() => { setCamera(initialCamera); setQuery(""); setHover(null); particles.current.clear(); setReset(v => v + 1); }, [resetKey]);
  useEffect(() => {
    const change = () => setVisible(document.visibilityState !== "hidden");
    const media = matchMedia("(prefers-reduced-motion: reduce)");
    const changeMotion = () => setReduced(media.matches);
    document.addEventListener("visibilitychange", change); media.addEventListener("change", changeMotion);
    return () => { document.removeEventListener("visibilitychange", change); media.removeEventListener("change", changeMotion); };
  }, []);
  // Physics updates SVG refs directly: live scan polling does not render React every frame.
  useEffect(() => {
    const fresh = particles.current.size === 0;
    const degrees = new Map<string, number>();
    for (const edge of graph.edges) for (const id of [edge.from, edge.to]) degrees.set(id, (degrees.get(id) || 0) + 1);
    const nodes: Particle[] = graph.nodes.map((node, index) => {
      const old = particles.current.get(node.id);
      const angle = index * Math.PI * (3 - Math.sqrt(5));
      const spread = Math.sqrt(index + 1) * 20;
      return { ...old, id: node.id, radius: node.cluster ? 9 : Math.min(9, 2.8 + Math.sqrt(degrees.get(node.id) || 0) * .8), x: old?.x ?? 500 + Math.cos(angle) * spread, y: old?.y ?? 300 + Math.sin(angle) * spread };
    });
    particles.current = new Map(nodes.map(node => [node.id, node]));
    const links: Link[] = graph.edges.map(edge => ({ id: edge.id, source: edge.from, target: edge.to }));
    const sim = forceSimulation(nodes).force("link", forceLink<Particle, Link>(links).id(node => node.id).distance(distance).strength(.28))
      .force("charge", forceManyBody<Particle>().strength(-repulsion).distanceMax(500))
      .force("collision", forceCollide<Particle>().radius(node => node.radius + 5))
      .force("x", forceX<Particle>(500).strength(.02)).force("y", forceY<Particle>(300).strength(.03))
      .force("center", forceCenter(500, 300).strength(.035)).alphaDecay(.025).stop();
    simulation.current = sim;
    const nodeElements = new Map(Array.from(svg.current?.querySelectorAll<SVGGElement>("[data-node-id]") || []).map(el => [el.dataset.nodeId!, el]));
    const edgeElements = new Map(Array.from(svg.current?.querySelectorAll<SVGLineElement>("[data-edge-id]") || []).map(el => [el.dataset.edgeId!, el]));
    const draw = () => {
      for (const node of nodes) {
        const el = nodeElements.get(node.id);
        if (el) { el.style.transform = `translate(${node.x}px, ${node.y}px)`; el.querySelector(".node-body")?.setAttribute("r", String(node.radius)); }
      }
      for (const link of links) {
        const a = link.source as Particle, b = link.target as Particle, el = edgeElements.get(link.id);
        if (el) { el.setAttribute("x1", String(a.x)); el.setAttribute("y1", String(a.y)); el.setAttribute("x2", String(b.x)); el.setAttribute("y2", String(b.y)); }
      }
    };
    // Settle a little before first paint; reduced motion shows a static settled map.
    sim.tick(nodes.length > 350 ? 45 : 100); draw(); sim.on("tick", draw);
    if (fresh && nodes.length) {
      const xs = nodes.map(n => n.x!), ys = nodes.map(n => n.y!);
      const left = Math.min(...xs), right = Math.max(...xs), top = Math.min(...ys), bottom = Math.max(...ys);
      const scale = Math.min(1, 820 / Math.max(1, right - left), 460 / Math.max(1, bottom - top));
      setCamera({ zoom: scale, x: 500 - (left + right) / 2 * scale, y: 300 - (top + bottom) / 2 * scale });
    }
    if (animate) sim.restart();
    return () => { sim.stop(); };
  }, [graph, repulsion, distance, reset, reduced]);
  useEffect(() => { if (animate) simulation.current?.alpha(.2).restart(); else simulation.current?.stop(); }, [animate]);
  const pointAt = (x: number, y: number): Point => {
    const matrix = svg.current?.getScreenCTM();
    if (!matrix || !svg.current) return { x: 0, y: 0 };
    const point = svg.current.createSVGPoint(); point.x = x; point.y = y;
    return point.matrixTransform(matrix.inverse());
  };
  const zoom = (factor: number) => setCamera(current => {
    const next = Math.min(5, Math.max(.25, current.zoom * factor));
    return { zoom: next, x: 500 - (500 - current.x) * next / current.zoom, y: 300 - (300 - current.y) * next / current.zoom };
  });
  useEffect(() => {
    const element = svg.current; if (!element) return;
    let frame = 0, pending = 0;
    let anchor: Point = { x: 500, y: 300 };
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      pending += wheelZoomDelta(event.deltaY, event.deltaMode, event.ctrlKey, zoomSensitivity / 100);
      anchor = pointAt(event.clientX, event.clientY);
      // Coalesce high-frequency trackpad events, without treating every pixel as a full step.
      if (!frame) frame = requestAnimationFrame(() => {
        const delta = pending, point = anchor;
        pending = 0; frame = 0;
        setCamera(current => zoomCameraAt(current, point, delta));
      });
    };
    element.addEventListener("wheel", wheel, { passive: false });
    return () => { element.removeEventListener("wheel", wheel); if (frame) cancelAnimationFrame(frame); };
  }, [zoomSensitivity, resetKey, reset]);
  const begin = (event: PointerEvent<SVGSVGElement>) => {
    if (event.button !== 0 || drag.current) return;
    const id = (event.target as Element).closest("[data-node-id]")?.getAttribute("data-node-id") as AttackGraphNodeId | null;
    const node = id ? particles.current.get(id) || null : null;
    drag.current = { pointerId: event.pointerId, id, client: { x: event.clientX, y: event.clientY }, point: pointAt(event.clientX, event.clientY), camera, node, origin: node ? { x: node.x!, y: node.y! } : { x: camera.x, y: camera.y }, fixed: { x: node?.fx, y: node?.fy } };
    moved.current = false; event.currentTarget.setPointerCapture(event.pointerId);
    if (node) { node.fx = node.x; node.fy = node.y; }
  };
  const move = (event: PointerEvent<SVGSVGElement>) => {
    const start = drag.current; if (!start || start.pointerId !== event.pointerId) return;
    const point = pointAt(event.clientX, event.clientY), dx = point.x - start.point.x, dy = point.y - start.point.y;
    if (Math.hypot(event.clientX - start.client.x, event.clientY - start.client.y) < 5 && !moved.current) return;
    moved.current = true;
    if (start.node) {
      start.node.fx = start.node.x = start.origin.x + dx / start.camera.zoom; start.node.fy = start.node.y = start.origin.y + dy / start.camera.zoom;
      simulation.current?.alpha(.2); simulation.current?.tick(); simulation.current?.on("tick")?.call(simulation.current);
      if (animate) simulation.current?.restart();
    } else setCamera({ ...start.camera, x: start.camera.x + dx, y: start.camera.y + dy });
  };
  const end = (event: PointerEvent<SVGSVGElement>) => {
    const start = drag.current;
    if (!start || start.pointerId !== event.pointerId) return;
    drag.current = null;
    if (start.node && !moved.current) {
      const node = particles.current.get(start.node.id) || start.node;
      node.fx = start.fixed.x; node.fy = start.fixed.y;
    }
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    // SVG pointer capture retargets the subsequent click to the canvas, not the node.
    // Activate the original node on pointer-up; dragging and cancellation never activate it.
    if (event.type === "pointerup" && !moved.current) {
      if (start.id) onSelect(start.id); else clearSelection();
    }
  };
  // Hover exposes a label, but only an explicit selection dims unrelated nodes.
  const focus = selected;
  const connected = new Set<string | null>([focus]);
  if (focus?.startsWith("finding:")) {
    // Trace recorded ancestry only; including every child of a source would recreate clutter.
    const queue: string[] = [focus];
    while (queue.length) {
      const child = queue.shift();
      for (const edge of graph.edges) if (edge.to === child && !connected.has(edge.from)) { connected.add(edge.from); queue.push(edge.from); }
    }
  } else for (const edge of graph.edges) {
    if (edge.from === focus) connected.add(edge.to);
    if (edge.to === focus) connected.add(edge.from);
  }
  const matches = new Set(graph.nodes.filter(node => filterNode(node, filter) && node.label.toLowerCase().includes(query.toLowerCase())).map(node => node.id));
  const inScope = new Set([...matches, ...graph.edges.flatMap(edge => matches.has(edge.from) ? [edge.to] : matches.has(edge.to) ? [edge.from] : [])]);
  // Cluster labels must remain clickable above the transparent hit areas of expanded leaves.
  const paintPriority = (node: AttackGraphNode) => node.cluster ? 2 : node.id === "target" || node.id.startsWith("source:") ? 1 : 0;
  const paintNodes = [...graph.nodes].sort((a, b) => paintPriority(a) - paintPriority(b));
  return <div className="evidence-graph-shell force-graph-shell" data-motion={animate ? "on" : "off"}>
    <div className="graph-view-controls">
      <button type="button" aria-label={t("Zoom out")} onClick={() => zoom(1 / 1.1)}><Minus size={14} /></button><span aria-live="polite">{Math.round(camera.zoom * 100)}%</span>
      <button type="button" aria-label={t("Zoom in")} onClick={() => zoom(1.1)}><Plus size={14} /></button>
      <button type="button" aria-label={t("Reset graph position")} onClick={() => { clearSelection(); onReset(); setHover(null); setQuery(""); setSettings(false); setCamera(initialCamera); particles.current.clear(); setReset(v => v + 1); }}><RotateCcw size={14} /></button>
      <button type="button" aria-label={t(motion ? "Pause graph motion" : "Resume graph motion")} aria-pressed={!motion} onClick={() => setMotion(value => !value)}>{motion ? <Pause size={14} /> : <Play size={14} />}</button>
      <button type="button" aria-label={t("Graph settings")} aria-expanded={settings} onClick={() => setSettings(v => !v)}><SlidersHorizontal size={14} /></button>
    </div>
    {settings && <div className="graph-settings"><label>{t("Search nodes")}<input value={query} onChange={e => setQuery(e.target.value)} /></label>
      <label>{t("Repulsion")}<input type="range" min="15" max="250" value={repulsion} onChange={e => setRepulsion(Number(e.target.value))} /></label>
      <label>{t("Link distance")}<input type="range" min="20" max="120" value={distance} onChange={e => setDistance(Number(e.target.value))} /></label>
      <label>{t("Zoom sensitivity")} · {zoomSensitivity}%<input type="range" min="25" max="150" value={zoomSensitivity} onChange={e => setZoomSensitivity(Number(e.target.value))} /></label>
      <label className="graph-checkbox"><input type="checkbox" checked={labels} onChange={e => setLabels(e.target.checked)} />{t("Show all labels")}</label></div>}
    <svg className="evidence-graph" ref={svg} viewBox="0 0 1000 600" aria-label={t("Interactive evidence graph")} tabIndex={0}
      onPointerDown={begin} onPointerMove={move} onPointerUp={end} onPointerCancel={end} onLostPointerCapture={end}
      onKeyDown={event => {
        if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); clearSelection(); setSettings(false); return; }
        if (event.target !== event.currentTarget) return;
        if (event.key === "+" || event.key === "=") zoom(1.1);
        else if (event.key === "-") zoom(1 / 1.1);
        else if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) { event.preventDefault(); setCamera(current => ({ ...current, x: current.x + (event.key === "ArrowLeft" ? 30 : event.key === "ArrowRight" ? -30 : 0), y: current.y + (event.key === "ArrowUp" ? 30 : event.key === "ArrowDown" ? -30 : 0) })); }
      }}>
      <g className="graph-camera" transform={`translate(${camera.x} ${camera.y}) scale(${camera.zoom})`}>
        {graph.edges.map(edge => <line key={edge.id} data-edge-id={edge.id} className={`force-edge ${focus && connected.has(edge.from) && connected.has(edge.to) ? "focused" : ""} ${!inScope.has(edge.from) || !inScope.has(edge.to) || focus && (!connected.has(edge.from) || !connected.has(edge.to)) ? "faded" : ""}`}><title>{t("Recorded scanner association")}</title></line>)}
        {paintNodes.map(node => {
          const hub = Boolean(node.cluster) || node.id === "target" || node.id.startsWith("source:") || !node.id.includes(":");
          const label = graphNodeLabel(node, true);
          const shown = labels || camera.zoom >= 1.6 || hub || node.id === hover || node.id === focus || connected.has(node.id) && !focus?.startsWith("cluster:");
          return <g key={node.id} data-node-id={node.id} role="button" tabIndex={0} aria-label={`${graphNodeLabel(node)} · ${graphMetricLabel(node.metric)}`} aria-pressed={node.id === selected} aria-expanded={node.cluster?.expanded}
            className={`network-node graph-node force-node ${node.cluster ? "cluster-node" : ""} severity-${node.severity} ${node.id === selected ? "selected" : ""} ${!inScope.has(node.id) || focus && !connected.has(node.id) ? "faded" : ""}`}
            onPointerEnter={() => setHover(node.id)} onPointerLeave={() => setHover(null)} onFocus={() => setHover(node.id)} onBlur={() => setHover(null)}
            onClick={event => { if (event.detail === 0) onSelect(node.id); }} onKeyDown={event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); event.stopPropagation(); onSelect(node.id); } }}>
            <title>{`${graphNodeLabel(node)}\n${graphMetricLabel(node.metric)}`}</title><rect x="-15" y="-15" width={shown ? Math.min(280, label.length * 6 + 32) : 30} height="30" fill="transparent" /><circle className="node-body" r="4" />{node.cluster && <><circle className="cluster-ring" r="13" /><text className="cluster-mark" textAnchor="middle" dominantBaseline="central">{node.cluster.expanded ? "−" : "+"}</text></>}
            {shown && <text className="force-label" x="12" y="4">{label.length > 42 ? `${label.slice(0, 40)}…` : label}</text>}
          </g>;
        })}
      </g>
    </svg>
    {!graph.nodes.length && <div className="graph-empty">{t("Start a scan to populate the attack graph.")}</div>}
    <div className="graph-map-caption"><span>{graph.nodes.length} {t("nodes")} · {graph.edges.length} {t("links")}{Boolean(graph.grouped) && ` · ${t("{count} discovery URLs grouped", { count: graph.grouped! })}`}{Boolean(graph.omitted) && ` · ${graph.omitted} ${t("additional records not displayed")}`}</span><span>{t("Drag nodes or background · Scroll to zoom · Enter to inspect")}</span></div>
  </div>;
}
