"""Small read-only web dashboard used by canopen_live_monitor_v2."""

from __future__ import annotations

import json
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>D65 CANopen monitor</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b0d0e;
      --surface: #151819;
      --surface-2: #1b1f20;
      --line: #2c3233;
      --line-soft: #222728;
      --text: #f1f3f2;
      --muted: #9da5a3;
      --green: #35d07f;
      --green-soft: #173a2a;
      --blue: #4e9ee9;
      --cyan: #36c5bd;
      --amber: #e7b84b;
      --red: #ef6461;
      --unknown: #626a69;
    }

    * { box-sizing: border-box; }

    html, body { min-height: 100%; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, "Segoe UI", Arial, sans-serif;
      font-size: 14px;
      letter-spacing: 0;
    }

    .shell { min-width: 320px; }

    .topbar {
      position: sticky;
      top: 0;
      z-index: 10;
      display: grid;
      grid-template-columns: minmax(240px, 1fr) auto;
      gap: 16px;
      align-items: center;
      min-height: 58px;
      padding: 9px 18px;
      border-bottom: 1px solid var(--line);
      background: rgba(11, 13, 14, 0.96);
      backdrop-filter: blur(8px);
    }

    .brand-row {
      display: flex;
      align-items: baseline;
      gap: 10px;
      min-width: 0;
    }

    h1 {
      margin: 0;
      font-size: 17px;
      font-weight: 700;
      white-space: nowrap;
    }

    .source {
      overflow: hidden;
      color: var(--muted);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 12px;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .connection {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }

    .connection-dot, .signal-dot {
      display: inline-block;
      flex: 0 0 auto;
      width: 10px;
      height: 10px;
      border: 1px solid #737b79;
      border-radius: 2px;
      background: var(--unknown);
    }

    .connection.live .connection-dot,
    .signal-dot.on {
      border-color: #69e7a4;
      background: var(--green);
      box-shadow: 0 0 0 2px rgba(53, 208, 127, 0.12);
    }

    .connection.error .connection-dot { border-color: var(--red); background: var(--red); }
    .signal-dot.off { border-color: #454c4b; background: #303534; }
    .signal-dot.unknown { border-color: #656d6b; background: transparent; }

    main { padding: 14px 18px 24px; }

    .metrics {
      display: grid;
      grid-template-columns: repeat(6, minmax(110px, 1fr));
      border: 1px solid var(--line);
      background: var(--surface);
    }

    .metric {
      min-width: 0;
      padding: 10px 12px;
      border-right: 1px solid var(--line);
    }

    .metric:last-child { border-right: 0; }
    .metric-label { color: var(--muted); font-size: 11px; text-transform: uppercase; }
    .metric-value { margin-top: 4px; overflow: hidden; font-size: 18px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
    .metric-value.small { font-family: Consolas, "Cascadia Mono", monospace; font-size: 13px; font-weight: 500; }

    .section { margin-top: 18px; }

    .section-head {
      display: flex;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
    }

    h2 { margin: 0; font-size: 14px; font-weight: 700; }
    .section-note { color: var(--muted); font-size: 12px; }

    .analog-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 10px;
    }

    .chart-card, .module, .panel {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
    }

    .chart-card { min-height: 210px; padding: 11px; }
    .chart-title { font-weight: 650; }
    .chart-value { margin-top: 3px; color: var(--cyan); font-family: Consolas, "Cascadia Mono", monospace; font-size: 12px; }
    .chart-meta { margin-top: 4px; color: var(--muted); font-family: Consolas, "Cascadia Mono", monospace; font-size: 11px; }
    .chart-series {
      display: flex;
      flex-wrap: wrap;
      gap: 4px 10px;
      margin-top: 6px;
      color: var(--muted);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 11px;
    }
    .series-item { display: inline-flex; align-items: center; gap: 5px; min-width: 0; }
    .series-swatch { width: 9px; height: 9px; border-radius: 2px; }
    .chart-card canvas { display: block; width: 100%; height: 150px; margin-top: 8px; }

    .empty-state {
      padding: 14px;
      border: 1px dashed #3b4241;
      color: var(--muted);
      background: #111415;
    }

    .signal-tools {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }

    input[type="search"], select {
      height: 30px;
      border: 1px solid var(--line);
      border-radius: 4px;
      outline: none;
      background: var(--surface);
      color: var(--text);
      font: inherit;
    }

    input[type="search"] { width: min(260px, 48vw); padding: 0 9px; }
    select { padding: 0 28px 0 8px; }
    input[type="search"]:focus, select:focus { border-color: var(--blue); }

    .check {
      display: inline-flex;
      gap: 6px;
      align-items: center;
      min-height: 30px;
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }

    .module-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
      gap: 10px;
    }

    .module { overflow: hidden; }

    .module-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-2);
    }

    .module-name { font-weight: 700; }
    .module-meta { color: var(--muted); font-family: Consolas, "Cascadia Mono", monospace; font-size: 11px; }

    .signal-row {
      display: grid;
      grid-template-columns: 12px 42px minmax(0, 1fr) auto;
      gap: 8px;
      align-items: center;
      min-height: 31px;
      padding: 5px 10px;
      border-bottom: 1px solid var(--line-soft);
    }

    .signal-row:last-child { border-bottom: 0; }
    .signal-pin, .signal-state { color: var(--muted); font-family: Consolas, "Cascadia Mono", monospace; font-size: 11px; }
    .signal-name { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .signal-state.on { color: var(--green); }

    .lower-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.6fr) minmax(300px, 0.7fr);
      gap: 10px;
      margin-top: 18px;
    }

    .panel { min-width: 0; overflow: hidden; }
    .panel-title { padding: 9px 11px; border-bottom: 1px solid var(--line); font-size: 13px; font-weight: 700; }
    .table-wrap { max-width: 100%; overflow: auto; }

    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { position: sticky; top: 0; z-index: 1; background: var(--surface-2); color: var(--muted); font-size: 10px; font-weight: 600; text-align: left; text-transform: uppercase; }
    th, td { height: 29px; padding: 5px 8px; border-bottom: 1px solid var(--line-soft); white-space: nowrap; }
    tr:last-child td { border-bottom: 0; }
    td.mono { font-family: Consolas, "Cascadia Mono", monospace; }
    .nmt-op { color: var(--green); }

    .events { max-height: 342px; overflow: auto; }

    .event {
      display: grid;
      grid-template-columns: 58px 12px minmax(0, 1fr) auto;
      gap: 8px;
      align-items: center;
      min-height: 34px;
      padding: 6px 9px;
      border-bottom: 1px solid var(--line-soft);
    }

    .event:last-child { border-bottom: 0; }
    .event-time, .event-value { font-family: Consolas, "Cascadia Mono", monospace; font-size: 11px; }
    .event-time { color: var(--muted); }
    .event-name { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .event-value { color: var(--green); }

    .footer-line {
      display: flex;
      gap: 12px;
      justify-content: space-between;
      margin-top: 12px;
      color: var(--muted);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 11px;
    }

    @media (max-width: 900px) {
      .metrics { grid-template-columns: repeat(3, minmax(100px, 1fr)); }
      .metric:nth-child(3) { border-right: 0; }
      .metric:nth-child(-n+3) { border-bottom: 1px solid var(--line); }
      .lower-grid { grid-template-columns: 1fr; }
    }

    @media (max-width: 620px) {
      .topbar { grid-template-columns: 1fr; gap: 4px; padding: 8px 10px; }
      .brand-row { display: block; }
      .source { margin-top: 3px; }
      main { padding: 10px; }
      .metrics { grid-template-columns: repeat(2, minmax(100px, 1fr)); }
      .metric { border-bottom: 1px solid var(--line); }
      .metric:nth-child(2n) { border-right: 0; }
      .metric:nth-last-child(-n+2) { border-bottom: 0; }
      .section-head { align-items: flex-start; flex-direction: column; }
      .signal-tools { width: 100%; }
      input[type="search"] { flex: 1; width: auto; min-width: 120px; }
      .module-grid { grid-template-columns: 1fr; }
      .footer-line { align-items: flex-start; flex-direction: column; gap: 4px; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand-row">
        <h1>FlexiROC D65 · CANopen</h1>
        <div class="source" id="source">waiting for parser</div>
      </div>
      <div class="connection" id="connection"><span class="connection-dot"></span><span id="connectionText">connecting</span></div>
    </header>

    <main>
      <section class="metrics" aria-label="Capture status">
        <div class="metric"><div class="metric-label">Mode</div><div class="metric-value" id="mode">-</div></div>
        <div class="metric"><div class="metric-label">Frames</div><div class="metric-value" id="frames">0</div></div>
        <div class="metric"><div class="metric-label">Bus time</div><div class="metric-value" id="duration">0.0 s</div></div>
        <div class="metric"><div class="metric-label">Signal changes</div><div class="metric-value" id="changes">0</div></div>
        <div class="metric"><div class="metric-label">Decode errors</div><div class="metric-value" id="errors">0</div></div>
        <div class="metric"><div class="metric-label">Last frame</div><div class="metric-value small" id="lastFrame">-</div></div>
      </section>

      <section class="section" id="analogSection">
        <div class="section-head">
          <h2>Analog signals</h2>
          <div class="section-note" id="analogNote"></div>
        </div>
        <div class="analog-grid" id="analogGrid"></div>
      </section>

      <section class="section">
        <div class="section-head">
          <h2>Digital signals</h2>
          <div class="signal-tools">
            <input id="signalSearch" type="search" placeholder="Filter signals" aria-label="Filter signals">
            <select id="nodeFilter" aria-label="Filter by node"><option value="">All nodes</option></select>
            <label class="check"><input id="activeOnly" type="checkbox"> Active only</label>
          </div>
        </div>
        <div class="module-grid" id="moduleGrid"></div>
      </section>

      <div class="lower-grid">
        <section class="panel">
          <div class="panel-title">Nodes and PDO process image</div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Node</th><th>NMT</th><th>TPDO1</th><th>TPDO2</th><th>TPDO3</th><th>TPDO4</th><th>RPDO1</th><th>RPDO2</th><th>RPDO3</th><th>RPDO4</th><th>Frames</th></tr></thead>
              <tbody id="nodeRows"></tbody>
            </table>
          </div>
        </section>

        <section class="panel">
          <div class="panel-title">Recent signal changes</div>
          <div class="events" id="events"></div>
        </section>
      </div>

      <section class="section panel">
        <div class="panel-title">CANopen service traffic</div>
        <div class="table-wrap">
          <table><thead><tr><th>Service</th><th>Frames</th><th>Share</th></tr></thead><tbody id="serviceRows"></tbody></table>
        </div>
      </section>

      <div class="footer-line"><span id="output"></span><span id="updated"></span></div>
    </main>
  </div>

  <script>
    const ui = {
      source: document.getElementById('source'), connection: document.getElementById('connection'),
      connectionText: document.getElementById('connectionText'), mode: document.getElementById('mode'),
      frames: document.getElementById('frames'), duration: document.getElementById('duration'),
      changes: document.getElementById('changes'), errors: document.getElementById('errors'),
      lastFrame: document.getElementById('lastFrame'), analogGrid: document.getElementById('analogGrid'),
      analogNote: document.getElementById('analogNote'), moduleGrid: document.getElementById('moduleGrid'),
      nodeRows: document.getElementById('nodeRows'), events: document.getElementById('events'),
      serviceRows: document.getElementById('serviceRows'), output: document.getElementById('output'),
      updated: document.getElementById('updated'), search: document.getElementById('signalSearch'),
      nodeFilter: document.getElementById('nodeFilter'), activeOnly: document.getElementById('activeOnly')
    };
    let latest = null;

    const text = (tag, value, className = '') => {
      const element = document.createElement(tag);
      if (className) element.className = className;
      element.textContent = value;
      return element;
    };

    function setConnection(phase, ok) {
      ui.connection.className = `connection ${ok ? 'live' : 'error'}`;
      ui.connectionText.textContent = phase || (ok ? 'connected' : 'disconnected');
    }

    function stateClass(value) {
      return value === true ? 'on' : value === false ? 'off' : 'unknown';
    }

    function renderMetrics(data) {
      ui.source.textContent = data.source || '-';
      ui.source.title = data.source || '';
      ui.mode.textContent = String(data.mode || '-').toUpperCase();
      ui.frames.textContent = Number(data.frames || 0).toLocaleString();
      ui.duration.textContent = `${Number(data.duration_seconds || 0).toFixed(1)} s`;
      ui.changes.textContent = Number(data.signal_changes || 0).toLocaleString();
      ui.errors.textContent = Number(data.decode_errors || 0).toLocaleString();
      ui.lastFrame.textContent = data.last_frame || '-';
      ui.lastFrame.title = data.last_frame || '';
      ui.output.textContent = data.output ? `parsed: ${data.output}` : '';
      ui.updated.textContent = `updated: ${new Date().toLocaleTimeString()}`;
      setConnection(data.phase || 'running', data.phase !== 'error');
    }

    const CHART_WINDOW_SECONDS = 30;
    const SERIES_COLORS = ['#4e9ee9', '#36c5bd', '#e7b84b', '#ef6461', '#b996ff', '#8bd17c'];

    function formatAxisTime(seconds) {
      if (!Number.isFinite(seconds)) return '+0s';
      return `+${seconds.toFixed(seconds >= 10 ? 0 : 1)}s`;
    }

    function drawChart(canvas, series) {
      const rect = canvas.getBoundingClientRect();
      const ratio = Math.max(1, window.devicePixelRatio || 1);
      canvas.width = Math.max(1, Math.round(rect.width * ratio));
      canvas.height = Math.max(1, Math.round(rect.height * ratio));
      const ctx = canvas.getContext('2d');
      ctx.scale(ratio, ratio);
      const w = rect.width, h = rect.height, leftPad = 34, rightPad = 8, topPad = 15, bottomPad = 24;
      const plotW = Math.max(1, w - leftPad - rightPad);
      const plotH = Math.max(1, h - topPad - bottomPad);
      ctx.strokeStyle = '#262c2d'; ctx.lineWidth = 1;
      for (let i = 0; i < 4; i++) {
        const y = topPad + plotH * i / 3;
        ctx.beginPath(); ctx.moveTo(leftPad, y); ctx.lineTo(w - rightPad, y); ctx.stroke();
      }
      const end = Math.max(
        0,
        ...series.flatMap(item => (item.samples || []).map(sample => Number(sample.time)).filter(Number.isFinite))
      );
      const start = Math.max(0, end - CHART_WINDOW_SECONDS);
      ctx.fillStyle = '#8f9896'; ctx.font = '10px Consolas, monospace';
      for (let i = 0; i <= 3; i++) {
        const tickTime = start + CHART_WINDOW_SECONDS * i / 3;
        const x = leftPad + plotW * i / 3;
        ctx.strokeStyle = '#303637';
        ctx.beginPath(); ctx.moveTo(x, topPad); ctx.lineTo(x, topPad + plotH); ctx.stroke();
        const label = formatAxisTime(tickTime);
        const labelWidth = ctx.measureText(label).width;
        const labelX = Math.min(Math.max(0, x - labelWidth / 2), w - labelWidth);
        ctx.fillText(label, labelX, h - 6);
      }
      const windowSeries = series.map(item => ({
        ...item,
        samples: (item.samples || [])
          .map(sample => ({time: Number(sample.time), value: Number(sample.value)}))
          .filter(sample => Number.isFinite(sample.time) && Number.isFinite(sample.value) && sample.time >= start && sample.time <= end)
      }));
      const values = windowSeries.flatMap(item => item.samples.map(sample => sample.value));
      if (values.length < 1) return;
      let min = Math.min(...values), max = Math.max(...values);
      if (min === max) { min -= 1; max += 1; }
      windowSeries.forEach((item, seriesIndex) => {
        if (item.samples.length < 1) return;
        const color = item.color || SERIES_COLORS[seriesIndex % SERIES_COLORS.length];
        ctx.strokeStyle = color; ctx.lineWidth = 1.7; ctx.lineJoin = 'round';
        ctx.beginPath();
        item.samples.forEach((sample, index) => {
          const x = leftPad + plotW * (sample.time - start) / CHART_WINDOW_SECONDS;
          const y = topPad + plotH - plotH * (sample.value - min) / (max - min);
          if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();
        if (item.samples.length === 1) {
          const sample = item.samples[0];
          const x = leftPad + plotW * (sample.time - start) / CHART_WINDOW_SECONDS;
          const y = topPad + plotH - plotH * (sample.value - min) / (max - min);
          ctx.fillStyle = color;
          ctx.beginPath(); ctx.arc(x, y, 2.5, 0, Math.PI * 2); ctx.fill();
        }
      });
      ctx.fillStyle = '#8f9896';
      ctx.fillText(max.toFixed(1), 2, topPad + 3); ctx.fillText(min.toFixed(1), 2, topPad + plotH + 3);
    }

    function shortSeriesName(channel) {
      const replacements = [
        [' actual current', ''], ['TRAMMING LEFT ', ''], ['TRAMMING RIGHT ', ''],
        ['COMPRESSOR TEMP ', ''], ['COOLING FAN ', ''], ['HYDRAULIC OIL AND COMPRESSOR OIL', 'HYD/OIL'],
        ['DIESEL MOTOR', 'DIESEL']
      ];
      let result = channel.name || channel.key || '';
      replacements.forEach(([from, to]) => { result = result.replace(from, to); });
      return result.replace(/\s+/g, ' ').trim();
    }

    function analogGroupKey(channel) {
      const key = channel.key || '';
      if (key.includes('Y206')) return 'CPU1.Y206';
      if (key.includes('Y207')) return 'CPU1.Y207';
      if (key.includes('S174')) return 'D553.S174';
      if (key.includes('S175')) return 'D553.S175';
      if (key.includes('Y501') || key.includes('Y504')) return 'CPU3.COOLING_FAN_CURRENT';
      if (key.includes('B147') || key.includes('B362') || key.includes('B366')) return 'CPU3.TEMPERATURES';
      if (key.includes('B301')) return 'CPU2.B301_ENCODER';
      if (key.includes('B172')) return 'CPU3.B172_DEPTH_ENCODER';
      return key;
    }

    function analogGroupTitle(key, channels) {
      const titles = {
        'CPU1.Y206': 'Y206 tramming left actual current',
        'CPU1.Y207': 'Y207 tramming right actual current',
        'D553.S174': 'S174 left tramming joystick',
        'D553.S175': 'S175 right tramming joystick',
        'CPU3.COOLING_FAN_CURRENT': 'Cooling fan actual currents',
        'CPU3.TEMPERATURES': 'Temperature channels',
        'CPU2.B301_ENCODER': 'B301 boom swing encoder',
        'CPU3.B172_DEPTH_ENCODER': 'B172_1 depth encoder raw'
      };
      return titles[key] || channels[0]?.name || key;
    }

    function groupAnalogChannels(channels) {
      const groups = new Map();
      channels.forEach(channel => {
        const key = analogGroupKey(channel);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(channel);
      });
      return Array.from(groups.entries()).map(([key, groupChannels]) => ({
        key,
        title: analogGroupTitle(key, groupChannels),
        channels: groupChannels
      }));
    }

    function renderAnalog(channels) {
      ui.analogGrid.replaceChildren();
      if (!channels || channels.length === 0) {
        ui.analogNote.textContent = '0 identified channels';
        ui.analogGrid.append(text('div', 'No analog channel mapping is available yet.', 'empty-state'));
        return;
      }
      ui.analogNote.textContent = `${channels.length} identified channel${channels.length === 1 ? '' : 's'}`;
      channels.forEach((channel, index) => {
        const card = document.createElement('article'); card.className = 'chart-card';
        card.append(text('div', channel.name, 'chart-title'));
        const numeric = Number(channel.value);
        const current = channel.value == null || !Number.isFinite(numeric) ? 'unknown' : `${numeric.toFixed(Math.abs(numeric) >= 100 ? 1 : 2)} ${channel.unit || ''}`.trim();
        card.append(text('div', current, 'chart-value'));
        const raw = channel.raw_value == null ? 'raw unknown' : `raw ${channel.raw_value} ${channel.raw_unit || ''}`.trim();
        card.append(text('div', `${channel.node_name || ''} ${channel.service || ''} ${channel.cob_id || ''} B${channel.byte} · ${raw}`, 'chart-meta'));
        const canvas = document.createElement('canvas'); canvas.setAttribute('aria-label', channel.name);
        card.append(canvas); ui.analogGrid.append(card);
        requestAnimationFrame(() => drawChart(canvas, channel.samples, index % 2 ? '#36c5bd' : '#4e9ee9'));
      });
    }

    function renderAnalog(channels) {
      ui.analogGrid.replaceChildren();
      if (!channels || channels.length === 0) {
        ui.analogNote.textContent = '0 identified channels';
        ui.analogGrid.append(text('div', 'No analog channel mapping is available yet.', 'empty-state'));
        return;
      }
      const groups = groupAnalogChannels(channels);
      ui.analogNote.textContent = `${channels.length} channels - ${groups.length} graphs - ${CHART_WINDOW_SECONDS}s window`;
      groups.forEach((group) => {
        const card = document.createElement('article'); card.className = 'chart-card';
        card.append(text('div', group.title, 'chart-title'));
        const values = group.channels.map(channel => {
          const numeric = Number(channel.value);
          const value = channel.value == null || !Number.isFinite(numeric)
            ? 'unknown'
            : `${numeric.toFixed(Math.abs(numeric) >= 100 ? 1 : 2)} ${channel.unit || ''}`.trim();
          return `${shortSeriesName(channel)} ${value}`;
        });
        card.append(text('div', values.join('  |  '), 'chart-value'));
        const meta = group.channels.map(channel => {
          const raw = channel.raw_value == null ? 'raw unknown' : `raw ${channel.raw_value} ${channel.raw_unit || ''}`.trim();
          return `${channel.node_name || ''} ${channel.service || ''} ${channel.cob_id || ''} B${channel.byte} - ${raw}`;
        });
        card.append(text('div', meta.join('  |  '), 'chart-meta'));
        const legend = document.createElement('div'); legend.className = 'chart-series';
        group.channels.forEach((channel, index) => {
          const item = document.createElement('span'); item.className = 'series-item';
          const swatch = document.createElement('span'); swatch.className = 'series-swatch';
          swatch.style.background = SERIES_COLORS[index % SERIES_COLORS.length];
          item.append(swatch, text('span', shortSeriesName(channel)));
          legend.append(item);
        });
        card.append(legend);
        const canvas = document.createElement('canvas'); canvas.setAttribute('aria-label', group.title);
        card.append(canvas); ui.analogGrid.append(card);
        const series = group.channels.map((channel, index) => ({
          name: shortSeriesName(channel),
          color: SERIES_COLORS[index % SERIES_COLORS.length],
          samples: channel.samples || []
        }));
        requestAnimationFrame(() => drawChart(canvas, series));
      });
    }

    function syncNodeFilter(modules) {
      const selected = ui.nodeFilter.value;
      const values = new Set(Array.from(ui.nodeFilter.options).map(option => option.value));
      modules.forEach(module => {
        const value = String(module.node_id);
        if (!values.has(value)) ui.nodeFilter.append(new Option(`${module.node_name} · ${module.node_id}`, value));
      });
      ui.nodeFilter.value = selected;
    }

    function renderSignals(modules) {
      syncNodeFilter(modules);
      const query = ui.search.value.trim().toLowerCase();
      const node = ui.nodeFilter.value;
      const activeOnly = ui.activeOnly.checked;
      ui.moduleGrid.replaceChildren();
      modules.filter(module => !node || String(module.node_id) === node).forEach(module => {
        const signals = module.signals.filter(signal => {
          const matches = !query || `${signal.name} ${signal.key} ${signal.pin}`.toLowerCase().includes(query);
          return matches && (!activeOnly || signal.value === true);
        });
        if (signals.length === 0) return;
        const card = document.createElement('article'); card.className = 'module';
        const head = document.createElement('div'); head.className = 'module-head';
        head.append(text('div', module.node_name, 'module-name'));
        head.append(text('div', `node ${module.node_id} · ${module.service} ${module.cob_id}`, 'module-meta'));
        card.append(head);
        signals.forEach(signal => {
          const row = document.createElement('div'); row.className = 'signal-row'; row.title = signal.name;
          row.append(text('span', '', `signal-dot ${stateClass(signal.value)}`));
          row.append(text('span', signal.location, 'signal-pin'));
          row.append(text('span', signal.name, 'signal-name'));
          row.append(text('span', signal.state, `signal-state ${stateClass(signal.value)}`));
          card.append(row);
        });
        ui.moduleGrid.append(card);
      });
      if (!ui.moduleGrid.children.length) ui.moduleGrid.append(text('div', 'No signals match the current filter.', 'empty-state'));
    }

    function renderNodes(nodes) {
      ui.nodeRows.replaceChildren();
      nodes.forEach(node => {
        const row = document.createElement('tr');
        row.append(text('td', node.node_id, 'mono'));
        row.append(text('td', node.name));
        row.append(text('td', node.heartbeat, node.heartbeat === 'operational' ? 'nmt-op' : ''));
        ['T1','T2','T3','T4','R1','R2','R3','R4'].forEach(key => row.append(text('td', node.pdo[key] || '-', 'mono')));
        row.append(text('td', Number(node.frames || 0).toLocaleString(), 'mono'));
        ui.nodeRows.append(row);
      });
    }

    function renderEvents(events) {
      ui.events.replaceChildren();
      if (!events || events.length === 0) {
        ui.events.append(text('div', 'No state transitions recorded.', 'empty-state'));
        return;
      }
      events.forEach(event => {
        const row = document.createElement('div'); row.className = 'event';
        row.append(text('span', `+${Number(event.offset_seconds || 0).toFixed(2)}s`, 'event-time'));
        row.append(text('span', '', `signal-dot ${stateClass(event.value)}`));
        row.append(text('span', event.name, 'event-name'));
        row.append(text('span', event.state, 'event-value'));
        ui.events.append(row);
      });
    }

    function renderServices(services, total) {
      ui.serviceRows.replaceChildren();
      Object.entries(services || {}).sort((a, b) => b[1] - a[1]).forEach(([name, count]) => {
        const row = document.createElement('tr');
        row.append(text('td', name)); row.append(text('td', Number(count).toLocaleString(), 'mono'));
        row.append(text('td', total ? `${(100 * count / total).toFixed(1)}%` : '0.0%', 'mono'));
        ui.serviceRows.append(row);
      });
    }

    function render(data) {
      latest = data;
      renderMetrics(data); renderAnalog(data.analog || []); renderSignals(data.digital_modules || []);
      renderNodes(data.nodes || []); renderEvents(data.events || []); renderServices(data.services || {}, data.frames || 0);
    }

    async function refresh() {
      try {
        const response = await fetch('/api/state', {cache: 'no-store'});
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        render(await response.json());
      } catch (error) {
        setConnection('disconnected', false);
      }
    }

    [ui.search, ui.nodeFilter, ui.activeOnly].forEach(control => control.addEventListener('input', () => {
      if (latest) renderSignals(latest.digital_modules || []);
    }));
    window.addEventListener('resize', () => { if (latest) renderAnalog(latest.analog || []); });
    refresh(); setInterval(refresh, 400);
  </script>
</body>
</html>
"""


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    """Avoid duplicate dashboard servers sharing one Windows TCP port."""

    allow_reuse_address = False

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class DashboardServer:
    """Serve a replaceable JSON snapshot and a self-contained dashboard page."""

    def __init__(self, host: str, port: int, open_browser: bool = True) -> None:
        self.host = host
        self.requested_port = port
        self.open_browser = open_browser
        self._payload = b"{}"
        self._payload_lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.actual_port = 0
        self.url = ""

    def update(self, snapshot: dict[str, Any]) -> None:
        payload = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        with self._payload_lock:
            self._payload = payload

    def _read_payload(self) -> bytes:
        with self._payload_lock:
            return self._payload

    def start(self) -> str:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path in ("/", "/index.html"):
                    self._send(200, "text/html; charset=utf-8", DASHBOARD_HTML.encode("utf-8"))
                elif path == "/api/state":
                    self._send(200, "application/json; charset=utf-8", owner._read_payload())
                elif path == "/favicon.ico":
                    self._send(204, "image/x-icon", b"")
                else:
                    self._send(404, "text/plain; charset=utf-8", b"Not found\n")

            def _send(self, status: int, content_type: str, payload: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:
                return

        last_error: OSError | None = None
        ports = (0,) if self.requested_port == 0 else range(self.requested_port, min(65536, self.requested_port + 20))
        for port in ports:
            try:
                self._server = ExclusiveThreadingHTTPServer((self.host, port), Handler)
                break
            except OSError as error:
                last_error = error
        if self._server is None:
            raise OSError(f"could not bind dashboard near port {self.requested_port}: {last_error}")

        self._server.daemon_threads = True
        actual_port = self._server.server_address[1]
        self.actual_port = int(actual_port)
        browser_host = "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host
        self.url = f"http://{browser_host}:{actual_port}/"
        self._thread = threading.Thread(target=self._server.serve_forever, name="d65-dashboard", daemon=True)
        self._thread.start()
        if self.open_browser:
            threading.Timer(0.25, webbrowser.open, args=(self.url,)).start()
        return self.url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._server = None
        self._thread = None
