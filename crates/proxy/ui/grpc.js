"use strict";
// The "gRPC" tab: decoded gRPC, gRPC-Web and protobuf messages of a flow (docs/grpc.md).
//
// Registers { id: "grpc", title: "gRPC", visible(flow), render(flow, container) } with
// app.js's `window.registerTab` (or queues it in `window.pendingTabs` until app.js runs).
// Data: GET /api/v1/flows/{id}/grpc. DOM only through createElement/textContent.

(function () {
  const KINDS = /^application\/(grpc(-web(-text)?)?(\+proto)?|x-protobuf|protobuf|x-google-protobuf)\s*(;|$)/i;

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function rawOf(flow) {
    return flow && flow.raw ? flow.raw : flow;
  }

  function contentType(headers) {
    for (const [name, value] of headers || []) {
      if (String(name).toLowerCase() === "content-type") return String(value);
    }
    return "";
  }

  function isGrpc(flow) {
    const raw = rawOf(flow);
    if (!raw || raw.type !== "exchange") return false;
    return KINDS.test(contentType(raw.request_headers)) || KINDS.test(contentType(raw.response_headers));
  }

  function request(path) {
    if (typeof api === "function") return api(path);
    let token = "";
    try {
      token = new URLSearchParams(location.hash.slice(1)).get("token") || sessionStorage.getItem("token") || "";
    } catch (_) { /* no storage */ }
    return fetch("/api/v1/" + path, { headers: { Authorization: "Bearer " + token } });
  }

  /** One value as a short summary line. */
  function scalar(field) {
    switch (field.type) {
      case "varint":
        return field.zigzag !== field.value && field.value.length < 6
          ? field.value + " (sint " + field.zigzag + ")" : field.value;
      case "fixed64": return field.value + " (double " + field.double + ")";
      case "fixed32": return field.value + " (float " + field.float + ")";
      case "packed_varints": return "[" + field.values.join(", ") + "] (packed varints, a guess)";
      case "bytes":
        return field.size + " bytes: " + field.base64 + (field.truncated ? "..." : "");
      default: return "";
    }
  }

  function fieldList(fields, depth) {
    const list = el("ul", depth === 0 ? "grpc-tree" : null);
    for (const field of fields || []) {
      const item = el("li");
      const label = [el("span", "grpc-num", field.field), el("span", "grpc-wire", " " + field.wire + " ")];
      if (field.type === "message") {
        const details = el("details");
        details.open = depth < 2;
        const summary = el("summary");
        summary.append(...label, el("span", "grpc-wire", "message, " + field.fields.length + " fields"));
        details.append(summary, fieldList(field.fields, depth + 1));
        item.append(details);
      } else if (field.type === "string") {
        item.append(...label, el("span", "grpc-str", JSON.stringify(field.value)));
      } else {
        item.append(...label, el("span", "grpc-val", scalar(field)));
      }
      list.append(item);
    }
    return list;
  }

  function messageView(m) {
    const box = el("details", "grpc-msg");
    box.open = true;
    let title = "#" + m.index + "  " + m.size + " B";
    if (m.compressed) title += "  compressed";
    box.append(el("summary", null, title));
    if (m.note) box.append(el("p", "grpc-note", m.note));
    if (m.decoded) {
      box.append(fieldList(m.decoded.fields, 0));
      if (m.decoded.error) box.append(el("p", "grpc-error", "Malformed: " + m.decoded.error));
      if (m.decoded.truncated) box.append(el("p", "grpc-note", "Field cap reached: tree cut short."));
    }
    return box;
  }

  function streamView(title, stream) {
    const section = el("section", "grpc-section");
    section.append(el("h3", null, title));
    if (!stream) {
      section.append(el("p", "grpc-note", "No response."));
      return section;
    }
    if (stream.messages.length === 0) section.append(el("p", "grpc-note", "No messages."));
    for (const m of stream.messages) section.append(messageView(m));
    if (stream.error) section.append(el("p", "grpc-error", stream.error));
    if (stream.truncated) {
      section.append(el("p", "grpc-note", "Incomplete: the body was cut by --body-limit or a cap was reached."));
    }
    return section;
  }

  function show(call, container) {
    const head = el("div", "grpc-head");
    const name = call.service ? "/" + call.service + "/" + call.method : "(no /Service/Method path)";
    head.append(el("span", "grpc-method", name), el("span", "grpc-note", call.kind));
    if (call.encoding) head.append(el("span", "grpc-note", "grpc-encoding " + call.encoding));
    if (call.status !== undefined) {
      const text = "grpc-status " + call.status + (call.status_name ? " " + call.status_name : "");
      head.append(el("span", "grpc-status " + (call.status === 0 ? "ok" : "bad"), text));
    } else {
      head.append(el("span", "grpc-note", "no grpc-status"));
    }
    container.append(head);
    if (call.message) container.append(el("p", "grpc-error", "grpc-message: " + call.message));
    container.append(streamView("Request", call.request), streamView("Response", call.response));
    if (call.trailers.length > 0) {
      const section = el("section", "grpc-section");
      section.append(el("h3", null, "Trailers"));
      const table = el("table", "grpc-trailers");
      for (const [k, v] of call.trailers) {
        const row = el("tr");
        row.append(el("td", null, k), el("td", null, v));
        table.append(row);
      }
      section.append(table);
      container.append(section);
    }
  }

  async function render(flow, container) {
    const raw = rawOf(flow);
    container.replaceChildren(el("p", "grpc-note", "Decoding..."));
    try {
      const response = await request("flows/" + raw.id + "/grpc");
      const body = await response.json();
      container.replaceChildren();
      if (!response.ok) {
        container.append(el("p", "grpc-error", body.error || "HTTP " + response.status));
        return;
      }
      show(body, container);
    } catch (e) {
      container.replaceChildren(el("p", "grpc-error", "Could not load: " + e));
    }
  }

  const tab = { id: "grpc", title: "gRPC", visible: isGrpc, render };

  function connect() {
    if (typeof window.registerTab === "function") window.registerTab(tab);
    else (window.pendingTabs = window.pendingTabs || []).push(tab);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", connect);
  else connect();
})();
