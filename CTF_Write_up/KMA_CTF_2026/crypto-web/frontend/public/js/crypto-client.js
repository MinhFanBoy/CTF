async function apiPost(url, body = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return await res.json();
}

async function apiGet(url) {
  const res = await fetch(url);
  return await res.json();
}

async function copyText(text) {
  const value = String(text);

  if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (error) {
      // Fall back below for browsers that expose the API but still deny writes.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "0";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);

  const selection = document.getSelection();
  const ranges = [];
  if (selection) {
    for (let i = 0; i < selection.rangeCount; i += 1) {
      ranges.push(selection.getRangeAt(i));
    }
  }

  textarea.focus();
  textarea.select();
  textarea.setSelectionRange(0, textarea.value.length);

  let copied = false;
  try {
    copied = typeof document.execCommand === "function" && document.execCommand("copy");
  } catch (error) {
    copied = false;
  }

  document.body.removeChild(textarea);
  if (selection) {
    selection.removeAllRanges();
    ranges.forEach((range) => selection.addRange(range));
  }

  if (!copied) {
    window.prompt("Copy manually:", value);
  }
  return copied;
}

function compactHex(hex, head = 40, tail = 40) {
  if (!hex || hex.length <= head + tail + 8) return hex || "";
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

function prettyJson(obj) {
  return JSON.stringify(obj, null, 2);
}
