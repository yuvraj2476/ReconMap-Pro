import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import type { Graph } from "../types";

const TYPE_COLORS: Record<string, string> = {
  domain: "#60a5fa",
  subdomain: "#38bdf8",
  ip: "#a78bfa",
  asn: "#c084fc",
  organization: "#e879f9",
  certificate: "#fbbf24",
  technology: "#34d399",
  url: "#94a3b8",
  api: "#fb923c",
  javascript: "#facc15",
  dns_record: "#22d3ee",
  hosting: "#2dd4bf",
  web_server: "#f472b6",
};

export default function AttackGraph({
  graph,
  onSelect,
  height = "100%",
}: {
  graph: Graph;
  onSelect?: (nodeId: string | null) => void;
  height?: string | number;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const elements: ElementDefinition[] = [
      ...graph.nodes.map((n) => ({
        data: {
          id: n.data.id,
          label: n.data.label,
          type: n.data.type,
          color: TYPE_COLORS[n.data.type] || "#94a3b8",
          score: n.data.score,
        },
      })),
      ...graph.edges.map((e) => ({
        data: {
          id: e.data.id,
          source: e.data.source,
          target: e.data.target,
          label: e.data.label,
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            "border-width": 2,
            "border-color": "#0b1220",
            "width": "mapData(score, 0, 100, 28, 56)",
            "height": "mapData(score, 0, 100, 28, 56)",
            "label": "data(label)",
            "color": "#e2e8f0",
            "font-size": "10px",
            "font-family": "ui-monospace, monospace",
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 6,
            "text-max-width": "120px",
            "text-wrap": "ellipsis",
            "text-outline-width": 2,
            "text-outline-color": "#060a14",
          },
        },
        {
          selector: "node[type='domain']",
          style: {
            "border-width": 3,
            "border-color": "#38bdf8",
            "font-size": "12px",
            "font-weight": "bold",
          },
        },
        {
          selector: "edge",
          style: {
            "width": 1.5,
            "line-color": "#334155",
            "target-arrow-color": "#334155",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "arrow-scale": 0.8,
            "opacity": 0.7,
            "label": "data(label)",
            "font-size": "8px",
            "color": "#64748b",
            "text-rotation": "autorotate",
            "text-background-color": "#0b1220",
            "text-background-opacity": 0.8,
            "text-background-padding": "2px",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-color": "#f8fafc",
            "border-width": 3,
            "overlay-color": "#38bdf8",
            "overlay-padding": 6,
            "overlay-opacity": 0.15,
          },
        },
        {
          selector: ".highlighted",
          style: {
            "border-color": "#facc15",
            "border-width": 3,
          },
        },
      ],
      layout: {
        name: "cose",
        animate: false,
        nodeRepulsion: 8000,
        idealEdgeLength: 100,
        edgeElasticity: 100,
        gravity: 0.25,
        numIter: 1200,
        padding: 30,
      } as cytoscape.LayoutOptions,
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.3,
    });

    cy.on("tap", "node", (evt) => {
      onSelect?.(evt.target.id());
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) onSelect?.(null);
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, onSelect]);

  return (
    <div className="relative w-full" style={{ height }}>
      <div ref={containerRef} className="cy-canvas absolute inset-0 rounded-xl" />
      <div className="absolute bottom-3 left-3 card px-3 py-2 text-[10px] text-slate-400 space-y-1 pointer-events-none">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-sky-400" /> Domain
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-orange-400" /> API
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> Technology
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-violet-400" /> IP / ASN
        </div>
        <div className="text-slate-500 mt-1">Node size = attention score</div>
      </div>
    </div>
  );
}
