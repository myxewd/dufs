/**
 * @typedef {object} PathItem
 * @property {"Dir"|"SymlinkDir"|"File"|"SymlinkFile"} path_type
 * @property {string} name
 * @property {number} mtime
 * @property {number} size
 */

/**
 * @typedef {object} DATA
 * @property {string} href
 * @property {string} uri_prefix
 * @property {"Index" | "Edit" | "View"} kind
 * @property {PathItem[]} paths
 * @property {boolean} allow_upload
 * @property {boolean} allow_delete
 * @property {boolean} allow_search
 * @property {boolean} allow_archive
 * @property {boolean} auth
 * @property {"builtin" | "oidc"} auth_type
 * @property {string} user
 * @property {boolean} dir_exists
 * @property {string} editable
 */

var DUFS_MAX_UPLOADINGS = 1;

/**
 * @type {DATA} DATA
 */
var DATA;

/**
 * @type {string}
 */
var DIR_EMPTY_NOTE;

/**
 * @type {PARAMS}
 * @typedef {object} PARAMS
 * @property {string} q
 * @property {string} sort
 * @property {string} order
 */
let PARAMS = Object.fromEntries(new URLSearchParams(window.location.search).entries());

const IFRAME_FORMATS = [
  ".pdf",
  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
  ".mp4", ".mov", ".avi", ".wmv", ".flv", ".webm",
  ".mp3", ".ogg", ".wav", ".m4a",
];

const MAX_SUBPATHS_COUNT = 1000;

const ICONS = {
  dir: `<svg height="16" viewBox="0 0 14 16" width="14"><path fill-rule="evenodd" d="M13 4H7V3c0-.66-.31-1-1-1H1c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1V5c0-.55-.45-1-1-1zM6 4H1V3h5v1z"></path></svg>`,
  symlinkFile: `<svg height="16" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M8.5 1H1c-.55 0-1 .45-1 1v12c0 .55.45 1 1 1h10c.55 0 1-.45 1-1V4.5L8.5 1zM11 14H1V2h7l3 3v9zM6 4.5l4 3-4 3v-2c-.98-.02-1.84.22-2.55.7-.71.48-1.19 1.25-1.45 2.3.02-1.64.39-2.88 1.13-3.73.73-.84 1.69-1.27 2.88-1.27v-2H6z"></path></svg>`,
  symlinkDir: `<svg height="16" viewBox="0 0 14 16" width="14"><path fill-rule="evenodd" d="M13 4H7V3c0-.66-.31-1-1-1H1c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1V5c0-.55-.45-1-1-1zM1 3h5v1H1V3zm6 9v-2c-.98-.02-1.84.22-2.55.7-.71.48-1.19 1.25-1.45 2.3.02-1.64.39-2.88 1.13-3.73C4.86 8.43 5.82 8 7.01 8V6l4 3-4 3H7z"></path></svg>`,
  file: `<svg height="16" viewBox="0 0 12 16" width="12"><path fill-rule="evenodd" d="M6 5H2V4h4v1zM2 8h7V7H2v1zm0 2h7V9H2v1zm0 2h7v-1H2v1zm10-7.5V14c0 .55-.45 1-1 1H1c-.55 0-1-.45-1-1V2c0-.55.45-1 1-1h7.5L12 4.5zM11 5L8 2H1v12h10V5z"></path></svg>`,
  download: `<svg width="16" height="16" viewBox="0 0 16 16"><path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/><path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/></svg>`,
  move: `<svg width="16" height="16" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M1.5 1.5A.5.5 0 0 0 1 2v4.8a2.5 2.5 0 0 0 2.5 2.5h9.793l-3.347 3.346a.5.5 0 0 0 .708.708l4.2-4.2a.5.5 0 0 0 0-.708l-4-4a.5.5 0 0 0-.708.708L13.293 8.3H3.5A1.5 1.5 0 0 1 2 6.8V2a.5.5 0 0 0-.5-.5z"/></svg>`,
  edit: `<svg width="16" height="16" viewBox="0 0 16 16"><path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168l10-10zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207 11.207 2.5zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293l6.5-6.5zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325z"/></svg>`,
  delete: `<svg width="16" height="16" viewBox="0 0 16 16"><path d="M6.854 7.146a.5.5 0 1 0-.708.708L7.293 9l-1.147 1.146a.5.5 0 0 0 .708.708L8 9.707l1.146 1.147a.5.5 0 0 0 .708-.708L8.707 9l1.147-1.146a.5.5 0 0 0-.708-.708L8 8.293 6.854 7.146z"/><path d="M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2zM9.5 3A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5v2z"/></svg>`,
  // open-in-new: a box with an outbound arrow, drawn with filled paths so it
  // inherits the same `svg { fill: var(--svg-primary) }` as the other actions
  view: `<svg width="16" height="16" viewBox="0 0 16 16"><path d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/><path d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/></svg>`,
  shield: `<svg width="16" height="16" viewBox="0 0 16 16"><path d="M8 0c-.7 1.3-2.2 2.1-4 2.1v5c0 3.2 1.9 6 4 6.9 2.1-.9 4-3.7 4-6.9v-5C10.2 2.1 8.7 1.3 8 0zm0 1.6c.9.6 1.9 1 3 1.2v4.8c0 2.2-1.2 4.2-3 5.3-1.8-1.1-3-3.1-3-5.3V2.8c1.1-.2 2.1-.6 3-1.2z"/></svg>`,
}

/**
 * @type Map<string, Uploader>
 */
const failUploaders = new Map();

/**
 * @type Element
 */
let $pathsTable;
/**
 * @type Element
 */
let $pathsTableHead;
/**
 * @type Element
 */
let $pathsTableBody;
/**
 * @type Element
 */
let $uploadersTable;
/**
 * @type Element
 */
let $emptyFolder;
/**
 * @type Element
 */
let $editor;
/**
 * @type Element
 */
let $loginBtn;
/**
 * @type Element
 */
let $logoutBtn;
/**
 * @type Element
 */
let $userName;

// manage unload event to prevent leaving with uploads in progress
const beforeUnloadHandler = (event) => {
  if (Uploader.queues.length > 0 || Uploader.runnings > 0) {
    event.preventDefault();
    event.returnValue = '';
    return ''; // for some browsers
  }
};


// The per-row icons are rendered as <use> references into one hidden sprite:
// the same markup repeated for every row dominates the generated HTML.
const ICON_DEFS = {};
for (const [name, markup] of Object.entries(ICONS)) {
  const match = /^<svg([^>]*)>([\s\S]*)<\/svg>$/.exec(markup.trim());
  const attrs = match[1];
  const attr = (key) => (new RegExp(key + '="([^"]*)"').exec(attrs) || [])[1] || "";
  ICON_DEFS[name] = { width: attr("width"), height: attr("height"), viewBox: attr("viewBox"), body: match[2] };
}

const ICON_SPRITE = `<svg aria-hidden="true" style="display:none">${Object.entries(ICON_DEFS)
  .map(([name, def]) => `<symbol id="i-${name}" viewBox="${def.viewBox}">${def.body}</symbol>`)
  .join("")}</svg>`;

/**
 * Render an icon from the sprite.
 * @param {string} name
 */
function iconSvg(name) {
  const def = ICON_DEFS[name];
  return `<svg height="${def.height}" viewBox="${def.viewBox}" width="${def.width}"><use href="#i-${name}"/></svg>`;
}

// Produce table when window loads
window.addEventListener("DOMContentLoaded", async () => {
  const $indexData = document.getElementById('index-data');
  if (!$indexData) {
    alert("No data");
    return;
  }

  DATA = JSON.parse(decodeBase64($indexData.innerHTML));
  DIR_EMPTY_NOTE = PARAMS.q ? 'No results' : DATA.dir_exists ? 'Empty folder' : 'Folder will be created when a file is uploaded';

  document.body.insertAdjacentHTML("afterbegin", ICON_SPRITE);

  await ready();
});

async function ready() {
  $pathsTable = document.querySelector(".paths-table");
  $pathsTableHead = document.querySelector(".paths-table thead");
  $pathsTableBody = document.querySelector(".paths-table tbody");
  $uploadersTable = document.querySelector(".uploaders-table");
  $emptyFolder = document.querySelector(".empty-folder");
  $editor = document.querySelector(".editor");
  $loginBtn = document.querySelector(".login-btn");
  $logoutBtn = document.querySelector(".logout-btn");
  $userName = document.querySelector(".user-name");

  window.addEventListener('beforeunload', beforeUnloadHandler);

  // Wire both views once: navigation between them no longer reloads the
  // document, so either can be shown at any time.
  await setupIndexPage();
  setupEditorPage();

  await applyPage(DATA, location.href, false);
}

class Uploader {
  /**
   *
   * @param {File} file
   * @param {string[]} pathParts
   */
  constructor(file, pathParts) {
    /**
     * @type Element
     */
    this.$status = null;
    /**
     * @type Element
     */
    this.$size = null;
    /**
     * @type Element
     */
    this.$percent = null;
    /**
     * @type Element
     */
    this.$speed = null;
    /**
     * @type Element
     */
    this.$eta = null;
    // speed ring buffer, mirrors curl's progress meter (6 records, one per
    // second, giving a 5-second window) so the displayed speed stays stable
    this.startTime = 0;
    this.speedRecords = 0;
    this.speedAmounts = [];
    this.speedTimes = [];
    this.currentSpeed = 0;
    this.uploadOffset = 0;
    this.lastUptime = 0;
    this.name = [...pathParts, file.name].join("/");
    this.idx = Uploader.globalIdx++;
    this.file = file;
    this.url = newUrl(this.name);
  }

  upload() {
    const { idx, name, url } = this;
    const encodedName = encodedStr(name);
    $uploadersTable.insertAdjacentHTML("beforeend", `
  <tr id="upload${idx}" class="uploader">
    <td class="path cell-icon">
      ${getPathSvg()}
    </td>
    <td class="path cell-name">
      <a href="${url}">${encodedName}</a>
    </td>
    <td class="cell-status" id="uploadStatus${idx}"></td>
    <td class="cell-size" id="uploadSize${idx}"></td>
    <td class="cell-percent" id="uploadPercent${idx}"></td>
    <td class="cell-speed" id="uploadSpeed${idx}"></td>
    <td class="cell-eta" id="uploadEta${idx}"></td>
  </tr>`);
    $uploadersTable.classList.remove("hidden");
    $emptyFolder.classList.add("hidden");
    this.$status = document.getElementById(`uploadStatus${idx}`);
    this.$percent = document.getElementById(`uploadPercent${idx}`);
    this.$size = document.getElementById(`uploadSize${idx}`);
    this.$speed = document.getElementById(`uploadSpeed${idx}`);
    this.$eta = document.getElementById(`uploadEta${idx}`);
    this.$status.textContent = "-";
    this.$percent.textContent = formatPercent(0);
    this.$size.textContent = formatUploadSize(0, this.file.size);
    this.$status.addEventListener("click", e => {
      const nodeId = e.target.id;
      const matches = /^retry(\d+)$/.exec(nodeId);
      if (matches) {
        const id = parseInt(matches[1]);
        let uploader = failUploaders.get(id);
        if (uploader) uploader.retry();
      }
    });
    Uploader.queues.push(this);
    Uploader.runQueue();
  }

  ajax() {
    const { url } = this;

    this.startTime = Date.now();
    this.lastUptime = this.startTime;
    this.speedRecords = 1;
    this.speedAmounts = [0];
    this.speedTimes = [0];
    this.currentSpeed = 0;
    this.$status.textContent = "↑";

    const ajax = new XMLHttpRequest();
    ajax.upload.addEventListener("progress", e => this.progress(e), false);
    ajax.addEventListener("readystatechange", () => {
      if (ajax.readyState === 4) {
        if (ajax.status >= 200 && ajax.status < 300) {
          this.complete();
        } else {
          if (ajax.status != 0) {
            this.fail(`${ajax.status} ${ajax.statusText}`);
          }
        }
      }
    })
    ajax.addEventListener("error", () => this.fail(), false);
    ajax.addEventListener("abort", () => this.fail(), false);
    if (this.uploadOffset > 0) {
      ajax.open("PATCH", url);
      ajax.setRequestHeader("X-Update-Range", "append");
      ajax.send(this.file.slice(this.uploadOffset));
    } else {
      ajax.open("PUT", url);
      ajax.send(this.file);
      // setTimeout(() => ajax.abort(), 3000);
    }
  }

  async retry() {
    const { url } = this;
    let res = await fetch(url, {
      method: "HEAD",
    });
    let uploadOffset = 0;
    if (res.status == 200) {
      let value = res.headers.get("content-length");
      uploadOffset = parseInt(value) || 0;
    }
    this.uploadOffset = uploadOffset;
    this.ajax();
  }

  progress(event) {
    const now = Date.now();
    this.calcSpeed(now - this.startTime, event.loaded);
    if (now - this.lastUptime < 300) return; // throttle update for safari
    this.lastUptime = now;
    const uploadedSize = event.loaded + this.uploadOffset;
    const [speedValue, speedUnit] = formatFileSize(this.currentSpeed);
    this.$status.textContent = "↑";
    this.$percent.textContent = formatPercent((uploadedSize / this.file.size) * 100);
    this.$size.textContent = formatUploadSize(uploadedSize, this.file.size);
    this.$speed.textContent = `${speedValue} ${speedUnit}/s`;
    this.$eta.textContent = formatDuration(this.currentSpeed > 0 ? (event.total - event.loaded) / this.currentSpeed : Infinity);
  }

  /**
   * Update the smoothed speed using curl's progress meter algorithm: keep a
   * 6-record ring buffer (one record per second, a 5-second window), add a
   * record at most once per second, and average over the buffered window.
   * @param {number} elapsed milliseconds since the transfer started
   * @param {number} amount bytes transferred so far
   */
  calcSpeed(elapsed, amount) {
    const records = 6;
    const iNext = this.speedRecords % records;
    let iLatest = iNext > 0 ? iNext - 1 : records - 1;
    if (elapsed - this.speedTimes[iLatest] < 1000) return;
    this.speedRecords++;
    iLatest = iNext;
    this.speedAmounts[iLatest] = amount;
    this.speedTimes[iLatest] = elapsed;
    const iOldest = this.speedRecords < records ? 0 : (iLatest + 1) % records;
    const duration = this.speedTimes[iLatest] - this.speedTimes[iOldest];
    const delta = this.speedAmounts[iLatest] - this.speedAmounts[iOldest];
    this.currentSpeed = duration > 0 ? delta / duration * 1000 : 0;
  }

  complete() {
    invalidateNavCache();
    this.$status.textContent = "✓";
    this.$percent.textContent = formatPercent(100);
    this.$size.textContent = formatUploadSize(this.file.size, this.file.size);
    this.$speed.textContent = "";
    this.$eta.textContent = "";
    failUploaders.delete(this.idx);
    Uploader.runnings--;
    Uploader.runQueue();
  }

  fail(reason = "") {
    this.$status.innerHTML = `<span title="${reason}">✗</span><span class="retry-btn" id="retry${this.idx}" title="Retry">↻</span>`;
    this.$speed.textContent = "";
    this.$eta.textContent = "";
    failUploaders.set(this.idx, this);
    Uploader.runnings--;
    Uploader.runQueue();
  }
}

Uploader.globalIdx = 0;

Uploader.runnings = 0;

Uploader.auth = false;

/**
 * @type Uploader[]
 */
Uploader.queues = [];


Uploader.runQueue = async () => {
  if (Uploader.runnings >= DUFS_MAX_UPLOADINGS) return;
  if (Uploader.queues.length == 0) return;
  Uploader.runnings++;
  let uploader = Uploader.queues.shift();
  if (!Uploader.auth) {
    Uploader.auth = true;
    try {
      await checkAuth();
    } catch {
      Uploader.auth = false;
    }
  }
  uploader.ajax();
}

/**
 * Add breadcrumb
 * @param {string} href
 * @param {string} uri_prefix
 */
function addBreadcrumb(href, uri_prefix) {
  const $breadcrumb = document.querySelector(".breadcrumb");
  let parts = [];
  if (href === "/") {
    parts = [""];
  } else {
    parts = href.split("/");
  }
  const len = parts.length;
  let path = uri_prefix;
  for (let i = 0; i < len; i++) {
    const name = parts[i];
    if (i > 0) {
      if (!path.endsWith("/")) {
        path += "/";
      }
      path += encodeURIComponent(name);
    }
    const encodedName = encodedStr(name);
    if (i === 0) {
      $breadcrumb.insertAdjacentHTML("beforeend", `<a href="${path}" title="Root"><svg width="16" height="16" viewBox="0 0 16 16"><path d="M6.5 14.5v-3.505c0-.245.25-.495.5-.495h2c.25 0 .5.25.5.5v3.5a.5.5 0 0 0 .5.5h4a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4a.5.5 0 0 0 .5-.5z"/></svg></a>`);
    } else if (i === len - 1) {
      $breadcrumb.insertAdjacentHTML("beforeend", `<b>${encodedName}</b>`);
    } else {
      $breadcrumb.insertAdjacentHTML("beforeend", `<a href="${path}">${encodedName}</a>`);
    }
    if (i !== len - 1) {
      $breadcrumb.insertAdjacentHTML("beforeend", `<span class="separator">/</span>`);
    }
  }
}

async function setupIndexPage() {
  // The page is wired once. Visibility and content are re-applied by
  // renderIndex() on every navigation, so client-side navigation can reuse
  // these handlers instead of reloading the document.
  setupDropzone();
  setupUploadFile();
  setupNewFolder();
  setupNewFile();
  setupSearch();
  setupIpWhitelist();
  setupAclDetails();
  setupClientNav();

  if (DATA.auth) {
    await setupAuth();
  }
}

/**
 * Render path table thead
 */
function hasAclColumn(list) {
  return DATA.has_acl && (DATA.paths || []).some(p => p[list]);
}

// Computed once per render: hasAclColumn() scans every path, so calling it
// from addPath() for every row made rendering O(n²).
let showAclRead = false;
let showAclWrite = false;

function renderPathsTableHead() {
  const headerItems = [
    {
      name: "name",
      props: `colspan="2"`,
      text: "Name",
    },
    {
      name: "mtime",
      props: ``,
      text: "Last Modified",
    },
    {
      name: "size",
      props: ``,
      text: "Size",
    }
  ];
  $pathsTableHead.insertAdjacentHTML("beforeend", `
    <tr>
      ${headerItems.map(item => {
    let svg = `<svg width="12" height="12" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M11.5 15a.5.5 0 0 0 .5-.5V2.707l3.146 3.147a.5.5 0 0 0 .708-.708l-4-4a.5.5 0 0 0-.708 0l-4 4a.5.5 0 1 0 .708.708L11 2.707V14.5a.5.5 0 0 0 .5.5zm-7-14a.5.5 0 0 1 .5.5v11.793l3.146-3.147a.5.5 0 0 1 .708.708l-4 4a.5.5 0 0 1-.708 0l-4-4a.5.5 0 0 1 .708-.708L4 13.293V1.5a.5.5 0 0 1 .5-.5z"/></svg>`;
    let order = "desc";
    if (PARAMS.sort === item.name) {
      if (PARAMS.order === "desc") {
        order = "asc";
        svg = `<svg width="12" height="12" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 1a.5.5 0 0 1 .5.5v11.793l3.146-3.147a.5.5 0 0 1 .708.708l-4 4a.5.5 0 0 1-.708 0l-4-4a.5.5 0 0 1 .708-.708L7.5 13.293V1.5A.5.5 0 0 1 8 1z"/></svg>`
      } else {
        svg = `<svg width="12" height="12" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 15a.5.5 0 0 0 .5-.5V2.707l3.146 3.147a.5.5 0 0 0 .708-.708l-4-4a.5.5 0 0 0-.708 0l-4 4a.5.5 0 1 0 .708.708L7.5 2.707V14.5a.5.5 0 0 0 .5.5z"/></svg>`
      }
    }
    const qs = new URLSearchParams({ ...PARAMS, order, sort: item.name }).toString();
    const icon = `<span>${svg}</span>`
    return `<th class="cell-${item.name}" ${item.props}><a href="?${qs}">${item.text}${icon}</a></th>`
  }).join("\n")}
      ${showAclRead ? `<th class="cell-acl-read">Read</th>` : ""}
      ${showAclWrite ? `<th class="cell-acl-write">Write</th>` : ""}
      ${DATA.allow_ip_whitelist ? `<th class="cell-whitelist">Whitelist</th>` : ""}
      <th class="cell-actions">Actions</th>
    </tr>
  `);
}

/**
 * Render path table tbody
 */
// Rows are appended in chunks: a directory with thousands of entries would
// otherwise block the main thread and make every later repaint (hover,
// scroll) proportional to the whole listing.
const ROW_CHUNK = 200;
let renderedRows = 0;

function renderPathsTableBody() {
  $pathsTableBody.innerHTML = "";
  renderedRows = 0;
  if (!DATA.paths || DATA.paths.length === 0) {
    $emptyFolder.textContent = DIR_EMPTY_NOTE;
    $emptyFolder.classList.remove("hidden");
    return;
  }
  $pathsTable.classList.remove("hidden");
  renderRowChunk();
  fillViewport();
}

function renderRowChunk() {
  const paths = DATA.paths || [];
  if (renderedRows >= paths.length) return;
  const end = Math.min(renderedRows + ROW_CHUNK, paths.length);
  let html = "";
  for (let i = renderedRows; i < end; i++) {
    const file = paths[i];
    if (file) html += pathRowHtml(file, i);
  }
  $pathsTableBody.insertAdjacentHTML("beforeend", html);
  renderedRows = end;
}

/**
 * Keep appending while the rendered rows do not fill the viewport yet.
 */
function fillViewport() {
  const paths = DATA.paths || [];
  while (renderedRows < paths.length && document.documentElement.scrollHeight <= window.innerHeight + 200) {
    renderRowChunk();
  }
}

function loadMoreRows() {
  const paths = DATA.paths || [];
  if (renderedRows >= paths.length) return;
  if (window.innerHeight + window.scrollY < document.documentElement.scrollHeight - 600) return;
  renderRowChunk();
  fillViewport();
}

window.addEventListener("scroll", loadMoreRows, { passive: true });
window.addEventListener("resize", fillViewport, { passive: true });


/**
 * Render the index page from DATA. Runs on first load and after every
 * client-side navigation.
 */
function renderIndex() {
  document.title = `Index of ${DATA.href} - Dufs`;
  DIR_EMPTY_NOTE = PARAMS.q ? 'No results' : DATA.dir_exists ? 'Empty folder' : 'Folder will be created when a file is uploaded';

  applyIndexChrome();

  showAclRead = hasAclColumn("allow_read");
  showAclWrite = hasAclColumn("allow_write");

  $pathsTableHead.innerHTML = "";
  $pathsTableBody.innerHTML = "";
  $pathsTable.classList.add("hidden");
  $emptyFolder.classList.add("hidden");
  $emptyFolder.textContent = "";

  renderPathsTableHead();
  renderPathsTableBody();

  if (DATA.user && DATA.auth_type !== "oidc") {
    setupDownloadWithToken();
  }
}

function toggleControl(selector, visible) {
  const $el = document.querySelector(selector);
  if ($el) $el.classList.toggle("hidden", !visible);
}

/**
 * Sync the toolbar buttons with the capabilities of the current directory.
 */
function applyIndexChrome() {
  if (DATA.allow_archive) {
    const $download = document.querySelector(".download");
    $download.href = baseUrl() + "?zip";
    $download.title = "Download folder as a .zip file";
    $download.classList.add("dlwt");
  }
  toggleControl(".download", DATA.allow_archive);
  toggleControl(".move-file", false);
  toggleControl(".delete-file", false);
  toggleControl(".save-btn", false);
  toggleControl(".upload-file", DATA.allow_upload);
  toggleControl(".new-folder", DATA.allow_upload);
  toggleControl(".new-file", DATA.allow_upload);
  toggleControl(".searchbar", DATA.allow_search);
  toggleControl(".ip-whitelist-btn", DATA.allow_ip_whitelist);
}

/* ---------------------- client-side navigation ---------------------- */

// Directory links navigate by fetching the next index page and swapping the
// table in place instead of reloading the document. Reloading costs the
// browser a commit + first-paint window (~50-100ms) during which hover,
// cursor and status-bar feedback are all frozen, which reads as a stutter.
const NAV_CACHE_MAX = 24;
const NAV_CACHE_TTL = 60000;
const navCache = new Map();
let navSeq = 0;
let prefetchTimer = 0;
let prefetchUrl = null;

/** Drop hover-prefetched pages after a mutation so they cannot go stale. */
function invalidateNavCache() {
  navCache.clear();
}

function cancelPrefetch() {
  clearTimeout(prefetchTimer);
  prefetchTimer = 0;
  prefetchUrl = null;
}

/**
 * Prefetch only once the pointer rests on a link: sweeping the mouse across a
 * long listing must not fire a request per row.
 */
function schedulePrefetch(url) {
  if (url === prefetchUrl) return;
  cancelPrefetch();
  prefetchUrl = url;
  prefetchTimer = setTimeout(() => {
    prefetchTimer = 0;
    if (prefetchUrl === url) fetchIndex(url);
  }, 80);
}

// Parameters that are not page requests: downloads, auth round trips and the
// plain-text fallback. Everything else can be navigated to in place.
const NON_PAGE_PARAMS = ["zip", "login", "logout", "noscript", "token", "tokengen"];

function navigationShape(data) {
  // Only the session identity has to stay stable; the page type may change
  // (index <-> editor) since both views live in the same document.
  return [data.auth, data.auth_type, data.user].join("|");
}

/**
 * Whether a link points at another page of this server that can be swapped in
 * place: breadcrumb, directory names and the sort headers of the table.
 * File links, downloads and auth round trips keep the normal navigation.
 */
function isIndexNavLink(a) {
  if (!a || !a.href) return false;
  if (a.target === "_blank" || a.hasAttribute("download")) return false;
  if (a.closest(".breadcrumb")) return true;
  if (a.closest(".paths-table thead")) return true;
  const $row = a.closest("tr[data-path-index]");
  if (!$row) return false;
  const item = DATA.paths && DATA.paths[Number($row.getAttribute("data-path-index"))];
  return !!item && item.path_type.endsWith("Dir");
}

function indexNavUrl(a) {
  const url = new URL(a.href, location.href);
  if (url.origin !== location.origin) return null;
  if (url.hash) return null;
  for (const key of NON_PAGE_PARAMS) {
    if (url.searchParams.has(key)) return null;
  }
  return url.href;
}

function parsePageData(text) {
  const doc = new DOMParser().parseFromString(text, "text/html");
  const $data = doc.getElementById("index-data");
  if (!$data) return null;
  try {
    const data = JSON.parse(decodeBase64($data.innerHTML));
    return data && (data.kind === "Index" || data.kind === "Edit" || data.kind === "View") ? data : null;
  } catch {
    return null;
  }
}

/**
 * Fetch a page, reusing a hover-prefetched response while it is fresh.
 * Resolves to null when the reply is not a page, e.g. a login redirect, an
 * error or a download.
 */
function fetchIndex(url) {
  const cached = navCache.get(url);
  if (cached && Date.now() - cached.time < NAV_CACHE_TTL) return cached.promise;
  const promise = fetch(url, {
    credentials: "same-origin",
    headers: { Accept: "text/html" },
  })
    .then(res => (res.ok && !res.redirected ? res.text() : null))
    .then(text => (text ? parsePageData(text) : null))
    .catch(() => null);
  if (navCache.size >= NAV_CACHE_MAX) {
    navCache.delete(navCache.keys().next().value);
  }
  navCache.set(url, { promise, time: Date.now() });
  return promise;
}

/**
 * Swap in another page without replacing the document.
 */
async function navigateTo(url, push = true) {
  const seq = ++navSeq;
  cancelPrefetch();
  const data = await fetchIndex(url);
  if (seq !== navSeq) return;
  if (!data || navigationShape(data) !== navigationShape(DATA)) {
    // Login state changed: fall back to a real navigation.
    location.href = url;
    return;
  }
  await applyPage(data, url, push);
}

/**
 * Re-fetch and re-render the current page in place, used after a mutation.
 */
async function refreshPage() {
  const url = location.href;
  invalidateNavCache();
  await navigateTo(url, false);
}

function setupClientNav() {
  history.replaceState({ dufs: true }, "", location.href);

  window.addEventListener("popstate", event => {
    if (event.state && event.state.dufs) {
      navigateTo(location.href, false);
    } else {
      location.reload();
    }
  });

  document.addEventListener("click", event => {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const a = event.target.closest && event.target.closest("a");
    if (!isIndexNavLink(a)) return;
    const url = indexNavUrl(a);
    if (!url) return;
    event.preventDefault();
    navigateTo(url);
  });

  // Prefetch on hover so a click usually has the next page in hand already.
  document.addEventListener("pointerover", event => {
    const a = event.target.closest && event.target.closest("a");
    if (!isIndexNavLink(a)) return;
    const url = indexNavUrl(a);
    if (url) schedulePrefetch(url);
  });

  document.addEventListener("pointerout", event => {
    const a = event.target.closest && event.target.closest("a");
    if (!a) return;
    const to = event.relatedTarget;
    if (to && to.nodeType && a.contains(to)) return;
    cancelPrefetch();
  });
}

/**
 * Build the markup of one path row.
 * @param {PathItem} file
 * @param {number} index
 */
function pathRowHtml(file, index) {
  const encodedName = encodedStr(file.name);
  let url = newUrl(file.name);
  let actionDelete = "";
  let actionDownload = "";
  let actionMove = "";
  let actionEdit = "";
  let actionView = "";
  let actionWhitelist = "";
  let isDir = file.path_type.endsWith("Dir");
  if (isDir) {
    url += "/";
    if (DATA.allow_archive) {
      actionDownload = `
      <div class="action-btn">
        <a class="dlwt" href="${url}?zip" title="Download folder as a .zip file" download>${iconSvg("download")}</a>
      </div>`;
    }
  } else {
    actionDownload = `
    <div class="action-btn" >
      <a class="dlwt" href="${url}" title="Download file" download>${iconSvg("download")}</a>
    </div>`;
  }
  if (DATA.allow_delete) {
    if (DATA.allow_upload) {
      actionMove = `<div onclick="movePath(${index})" class="action-btn" id="moveBtn${index}" title="Move & Rename">${iconSvg("move")}</div>`;
      if (!isDir) {
        actionEdit = `<a class="action-btn" title="Edit file" target="_blank" href="${url}?edit">${iconSvg("edit")}</a>`;
      }
    }
    actionDelete = `
    <div onclick="deletePath(${index})" class="action-btn" id="deleteBtn${index}" title="Delete">${iconSvg("delete")}</div>`;
  }
  if (!actionEdit && !isDir) {
    actionView = `<a class="action-btn" title="Open file" target="_blank" href="${url}?view">${iconSvg("view")}</a>`;
  }
  if (DATA.allow_ip_whitelist) {
    actionWhitelist = `<div onclick="manageWhitelist(${index})" class="action-btn" title="IP whitelist">${iconSvg("shield")}</div>`;
  }
  let actionCell = `
  <td class="cell-actions">
    ${actionDownload}
    ${actionView}
    ${actionMove}
    ${actionDelete}
    ${actionEdit}
    ${actionWhitelist}
  </td>`;

  let sizeDisplay = isDir ? formatDirSize(file.size) : formatFileSize(file.size).join(" ");

  return `<tr id="addPath${index}" data-path-index="${index}">
  <td class="path cell-icon">
    ${getPathSvg(file.path_type)}
  </td>
  <td class="path cell-name">
    <a href="${url}" ${isDir ? "" : `target="_blank"`}>${encodedName}</a>
  </td>
  <td class="cell-mtime">${formatMtime(file.mtime)}</td>
  <td class="cell-size">${sizeDisplay}</td>
  ${showAclRead ? `<td class="cell-acl-read">${listCell(file.allow_read)}</td>` : ""}
  ${showAclWrite ? `<td class="cell-acl-write">${listCell(file.allow_write)}</td>` : ""}
  ${DATA.allow_ip_whitelist ? `<td class="cell-whitelist">${listCell(file.whitelist)}</td>` : ""}
  ${actionCell}
</tr>`;
}

function setupDropzone() {
  ["drag", "dragstart", "dragend", "dragover", "dragenter", "dragleave", "drop"].forEach(name => {
    document.addEventListener(name, e => {
      e.preventDefault();
      e.stopPropagation();
    });
  });
  document.addEventListener("drop", async e => {
    if (DATA.kind !== "Index") return;
    if (!e.dataTransfer.items[0].webkitGetAsEntry) {
      const files = Array.from(e.dataTransfer.files).filter(v => v.size > 0);
      for (const file of files) {
        new Uploader(file, []).upload();
      }
    } else {
      const entries = [];
      const len = e.dataTransfer.items.length;
      for (let i = 0; i < len; i++) {
        entries.push(e.dataTransfer.items[i].webkitGetAsEntry());
      }
      addFileEntries(entries, []);
    }
  });
}

async function setupAuth() {
  if (DATA.user) {
    $logoutBtn.classList.remove("hidden");
    $logoutBtn.addEventListener("click", logout);
    $userName.textContent = DATA.user;
  } else {
    // Unauthenticated visitors are the `guest` identity; the login button
    // starts whichever authentication the server is configured for.
    $loginBtn.classList.remove("hidden");
    $loginBtn.addEventListener("click", () => {
      location.href = baseUrl() + "?login";
    });
  }
}

function setupDownloadWithToken() {
  document.querySelectorAll("a.dlwt").forEach(link => {
    // The table is re-rendered on every navigation while toolbar links
    // survive, so bind each anchor only once.
    if (link.dataset.dlwtBound) return;
    link.dataset.dlwtBound = "1";
    link.addEventListener("click", async e => {
      e.preventDefault();
      try {
        const link = e.currentTarget || e.target;
        const originalHref = link.getAttribute("href");
        const tokengenUrl = new URL(originalHref);
        tokengenUrl.searchParams.set("tokengen", "");
        const res = await fetch(tokengenUrl);
        if (!res.ok) throw new Error("Failed to fetch token");
        const token = await res.text();
        const downloadUrl = new URL(originalHref);
        downloadUrl.searchParams.set("token", token);
        const tempA = document.createElement("a");
        tempA.href = downloadUrl.toString();
        tempA.download = "";
        document.body.appendChild(tempA);
        tempA.click();
        document.body.removeChild(tempA);
      } catch (err) {
        alert(`Failed to download, ${err.message}`);
      }
    });
  });
}

function setupSearch() {
  const $searchbar = document.querySelector(".searchbar");
  $searchbar.addEventListener("submit", event => {
    event.preventDefault();
    const formData = new FormData($searchbar);
    const q = formData.get("q");
    let href = baseUrl();
    if (q) {
      href += "?q=" + q;
    }
    navigateTo(href);
  });
  if (PARAMS.q) {
    document.getElementById('search').value = PARAMS.q;
  }
}

function setupUploadFile() {
  document.getElementById("file").addEventListener("change", async e => {
    const files = e.target.files;
    for (let file of files) {
      new Uploader(file, []).upload();
    }
  });
}

function setupNewFolder() {
  const $newFolder = document.querySelector(".new-folder");
  $newFolder.addEventListener("click", () => {
    const name = prompt("Enter folder name");
    if (name) createFolder(name);
  });
}

function setupNewFile() {
  const $newFile = document.querySelector(".new-file");
  $newFile.addEventListener("click", () => {
    const name = prompt("Enter file name");
    if (name) createFile(name);
  });
}

var ACL_PATH = "";
var ACL_VERSION = "";
var ACL_X_USERS = [];
var ACL_CHAIN = [];
var ACL_OWN_BEFORE = { allow_read: [], allow_write: [], deny_read: [] };
var ACL_INHERITED = { allow_read: [], allow_write: [], deny_read: [] };
var ACL_BEFORE = { allow_read: [], allow_write: [], deny_read: [] };
var ACL_DATA = { ips: [], allow_read: [], allow_write: [], deny_read: [] };
var ACL_TFTP = false;
var ACL_TFTP_BEFORE = false;
var ACL_GUEST_READABLE = true;
var ACL_OWN_NULL = { allow_read: true, allow_write: true, deny_read: true };
var ACL_IPS_BEFORE = [];

function setupIpWhitelist() {
  const $modal = document.getElementById("whitelistModal");
  const $btn = document.querySelector(".ip-whitelist-btn");
  $btn.classList.remove("hidden");
  $btn.addEventListener("click", () => openWhitelistModal(currentDirPath()));

  for (const id of ["whitelistModal", "aclDiffModal"]) {
    const $m = document.getElementById(id);
    // Closing only happens through the explicit X / Confirm buttons;
    // clicking the backdrop must not discard an edit in progress.
    $m.querySelector(".modal-close").addEventListener("click", () => $m.classList.add("hidden"));
  }

  $modal.querySelector(".save-rule-btn").addEventListener("click", saveWhitelist);
  $modal.querySelector(".remove-rule-btn").addEventListener("click", removeWhitelist);

  const $diff = document.getElementById("aclDiffModal");
  $diff.querySelector(".acl-diff-cancel").addEventListener("click", () => $diff.classList.add("hidden"));
  $diff.querySelector(".acl-diff-confirm").addEventListener("click", confirmAclSave);

  const $tftp = $modal.querySelector(".acl-tftp-input");
  if ($tftp) {
    $tftp.addEventListener("change", () => {
      if ($tftp.disabled) {
        $tftp.checked = false;
        ACL_TFTP = false;
        return;
      }
      ACL_TFTP = $tftp.checked;
    });
  }

  $modal.querySelectorAll(".acl-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      const list = tab.getAttribute("data-list");
      $modal.querySelectorAll(".acl-tab").forEach(t => t.classList.toggle("active", t === tab));
      $modal.querySelectorAll(".acl-panel").forEach(panel => {
        panel.classList.toggle("hidden", panel.getAttribute("data-panel") !== list);
      });
    });
  });

  $modal.addEventListener("click", e => {
    const remove = e.target.closest(".acl-tag-remove");
    if (!remove) return;
    const list = remove.getAttribute("data-list");
    const user = remove.getAttribute("data-user");
    if (user) {
      removeAclMember(list, user);
      renderAclLists();
      $modal.querySelector(`.acl-tags[data-list="${list}"] .acl-tag-input`)?.focus();
    }
  });

  $modal.addEventListener("click", e => {
    const $tags = e.target.closest(".acl-tags");
    if (!$tags || e.target.closest(".acl-tag-remove")) return;
    $tags.querySelector(".acl-tag-input")?.focus();
  });

  $modal.addEventListener("keydown", e => {
    if (!e.target.classList.contains("acl-tag-input")) return;
    if (e.key !== "Enter" && e.key !== "Tab") return;
    const value = e.target.value.trim();
    if (!value) return;
    e.preventDefault();
    const $tags = e.target.closest(".acl-tags");
    const list = $tags.getAttribute("data-list");
    if (list === "deny_read" && ACL_X_USERS.includes(value)) {
      alert(`${value} has x and cannot be denied.`);
      return;
    }
    addAclMember(list, value);
    renderAclLists();
    $modal.querySelector(`.acl-tags[data-list="${list}"] .acl-tag-input`)?.focus();
  });

}

var LIST_DETAILS_ITEMS = [];
var LIST_DETAILS_FILTER = "";

function setupAclDetails() {
  const $details = document.getElementById("listDetailsModal");
  if (!$details) return;
  $details.querySelector(".modal-close").addEventListener("click", () => $details.classList.add("hidden"));
  $details.addEventListener("click", e => {
    if (e.target === $details) $details.classList.add("hidden");
  });
  const $search = $details.querySelector(".list-details-search");
  $search.addEventListener("keydown", e => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    LIST_DETAILS_FILTER = e.target.value.trim();
    e.target.value = "";
    renderListDetails();
  });
  document.addEventListener("click", e => {
    const link = e.target.closest(".acl-list-link");
    if (!link) return;
    e.preventDefault();
    LIST_DETAILS_ITEMS = (link.getAttribute("data-full") || "").split(", ").filter(Boolean);
    LIST_DETAILS_FILTER = "";
    $search.value = "";
    renderListDetails();
    $details.classList.remove("hidden");
    $search.focus();
  });
}

function renderListDetails() {
  const $details = document.getElementById("listDetailsModal");
  const filter = LIST_DETAILS_FILTER.toLowerCase();
  const items = filter
    ? LIST_DETAILS_ITEMS.filter(item => item.toLowerCase().includes(filter))
    : LIST_DETAILS_ITEMS;
  $details.querySelector(".modal-head b").textContent = LIST_DETAILS_FILTER
    ? `Full list - ${LIST_DETAILS_FILTER}`
    : "Full list";
  $details.querySelector(".list-details-body").innerHTML = items.length
    ? `<ul class="list-details">${items.map(item => `<li>${encodedStr(item)}</li>`).join("")}</ul>`
    : `<div class="list-details-empty">No matches</div>`;
}

function currentDirPath() {
  return DATA.href === "/" ? "/" : DATA.href;
}

function aclUrl(path) {
  return DATA.uri_prefix + "__dufs__/acl?path=" + encodeURIComponent(path);
}

async function openWhitelistModal(path) {
  const $modal = document.getElementById("whitelistModal");
  $modal.querySelector(".modal-status").textContent = "";
  $modal.classList.remove("hidden");
  $modal.querySelector(".whitelist-path").textContent = path;
  try {
    const res = await fetch(aclUrl(path));
    await assertResOK(res);
    const data = await res.json();
    ACL_PATH = path;
    ACL_VERSION = data.version || "";
    ACL_X_USERS = data.x_users || [];
    ACL_CHAIN = data.chain || [];
    const own = data.own || {};
    const inherited = data.inherited || {};
    ACL_OWN_BEFORE = {
      allow_read: [...(own.allow_read || [])],
      allow_write: [...(own.allow_write || [])],
      deny_read: [...(own.deny_read || [])],
    };
    ACL_INHERITED = {
      allow_read: [...(inherited.allow_read || [])],
      allow_write: [...(inherited.allow_write || [])],
      deny_read: [...(inherited.deny_read || [])],
    };
    ACL_BEFORE = effectiveLists(ACL_OWN_BEFORE, ACL_INHERITED);
    ACL_DATA = {
      ips: data.ips === null || data.ips === undefined ? ["0.0.0.0/0", "::/0"] : data.ips,
      allow_read: [...ACL_OWN_BEFORE.allow_read],
      allow_write: [...ACL_OWN_BEFORE.allow_write],
      deny_read: [...ACL_OWN_BEFORE.deny_read],
    };
    ACL_OWN_NULL = {
      allow_read: own.allow_read === null || own.allow_read === undefined,
      allow_write: own.allow_write === null || own.allow_write === undefined,
      deny_read: own.deny_read === null || own.deny_read === undefined,
    };
    ACL_GUEST_READABLE = data.guest_readable !== false;
    ACL_TFTP_BEFORE = !!data.enable_tftp;
    ACL_TFTP = ACL_TFTP_BEFORE;
    ACL_IPS_BEFORE = [...ACL_DATA.ips];
    $modal.querySelector(".whitelist-input").value = ACL_DATA.ips.join(", ");
    renderAclLists();
  } catch (err) {
    $modal.classList.add("hidden");
    alert(`Failed to load acl, ${err.message}`);
  }
}

function normalizeAclLists() {
  ACL_DATA.allow_read = ACL_DATA.allow_read.filter(u => !ACL_DATA.deny_read.includes(u));
  ACL_DATA.allow_write = ACL_DATA.allow_write.filter(u => !ACL_DATA.deny_read.includes(u));
  for (const user of ACL_DATA.allow_write) {
    if (!ACL_DATA.allow_read.includes(user)) ACL_DATA.allow_read.push(user);
  }
  for (const list of ["allow_read", "allow_write", "deny_read"]) {
    ACL_DATA[list] = [...new Set(ACL_DATA[list])];
  }
}

function addAclMember(list, user) {
  if (!ACL_DATA[list] || !user) return;
  // x users always win over the acl and cannot be denied
  if (list === "deny_read" && ACL_X_USERS.includes(user)) return;
  if (list === "deny_read") {
    ACL_DATA.allow_read = ACL_DATA.allow_read.filter(u => u !== user);
    ACL_DATA.allow_write = ACL_DATA.allow_write.filter(u => u !== user);
  } else if (list === "allow_write") {
    ACL_DATA.deny_read = ACL_DATA.deny_read.filter(u => u !== user);
    if (!ACL_DATA.allow_read.includes(user)) ACL_DATA.allow_read.push(user);
  } else {
    ACL_DATA.deny_read = ACL_DATA.deny_read.filter(u => u !== user);
  }
  if (!ACL_DATA[list].includes(user)) ACL_DATA[list].push(user);
  normalizeAclLists();
}

function removeAclMember(list, user) {
  if (!ACL_DATA[list]) return;
  ACL_DATA[list] = ACL_DATA[list].filter(u => u !== user);
  if (list === "allow_read") {
    ACL_DATA.allow_write = ACL_DATA.allow_write.filter(u => u !== user);
  }
  normalizeAclLists();
}

function ownMentioned(own) {
  return new Set([...own.allow_read, ...own.allow_write, ...own.deny_read]);
}

function effectiveLists(own, inherited) {
  const mentioned = ownMentioned(own);
  const out = {
    allow_read: [...own.allow_read],
    allow_write: [...own.allow_write],
    deny_read: [...own.deny_read],
  };
  for (const list of ["allow_read", "allow_write", "deny_read"]) {
    for (const user of inherited[list] || []) {
      if (!mentioned.has(user) && !out[list].includes(user)) out[list].push(user);
    }
  }
  return out;
}

function renderAclLists() {
  const $modal = document.getElementById("whitelistModal");
  const mentioned = ownMentioned(ACL_DATA);
  for (const list of ["allow_read", "allow_write", "deny_read"]) {
    const $tags = $modal.querySelector(`.acl-tags[data-list="${list}"]`);
    if (!$tags) continue;
    const own = list === "deny_read"
      ? ACL_DATA[list].filter(user => !ACL_X_USERS.includes(user))
      : ACL_DATA[list];
    const inherited = (ACL_INHERITED[list] || []).filter(
      user => !mentioned.has(user) && !own.includes(user),
    );
    const tags = [
      // inherited (locked) tags are always kept in front of the editable ones
      ...inherited.map(user => tagHtml(user, list, true)),
      ...own.map(user => tagHtml(user, list, false)),
      `<input class="acl-tag-input" type="text" spellcheck="false" autocomplete="off" placeholder="Add a user and press Tab">`,
    ];
    $tags.innerHTML = tags.join("");
  }
  updateTftpState();
}

function updateTftpState() {
  const $modal = document.getElementById("whitelistModal");
  const $input = $modal.querySelector(".acl-tftp-input");
  if (!$input) return;
  const eff = effectiveLists(ACL_DATA, ACL_INHERITED);
  const guestMentioned = eff.allow_read.includes("guest")
    || eff.allow_write.includes("guest")
    || eff.deny_read.includes("guest");
  // When the edited lists mention guest they decide; otherwise fall back to
  // the server's view, which also accounts for --auth and inherited rules.
  const guestReadable = guestMentioned
    ? !eff.deny_read.includes("guest")
    : ACL_GUEST_READABLE;
  if (!guestReadable) {
    ACL_TFTP = false;
    $input.checked = false;
  } else {
    $input.checked = ACL_TFTP;
  }
  $input.disabled = !guestReadable;
  $input.title = guestReadable
    ? ""
    : "Disabled: guest cannot read this path. Grant guest read access first.";
}

function tagHtml(user, list, inherited) {
  const mark = ACL_X_USERS.includes(user) ? '<span class="acl-x-mark">*</span>' : "";
  const name = `${encodedStr(user)}${mark}`;
  if (inherited) {
    return `<span class="acl-tag acl-tag-locked">${name}</span>`;
  }
  return `<span class="acl-tag">${name}<button class="acl-tag-remove" type="button" data-list="${list}" data-user="${encodedStr(user)}" title="Remove">&times;</button></span>`;
}

function parseWhitelistInput(value) {
  return value
    .split(",")
    .map(v => v.trim())
    .filter(v => v.length > 0);
}

function listCell(value) {
  if (value === "blocked") {
    return `<span class="whitelist-blocked">blocked</span>`;
  }
  if (!value) return "";
  const full = String(value);
  if (full.length <= 24) return encodedStr(full);
  return `<a href="#" class="acl-list-link" data-full="${encodedStr(full)}">${encodedStr(full.slice(0, 24))}...</a>`;
}

function aclPermOf(lists, user) {
  if ((lists.deny_read || []).includes(user)) return "-";
  if ((lists.allow_write || []).includes(user)) return "rw";
  if ((lists.allow_read || []).includes(user)) return "r";
  return "-";
}

function aclChanges() {
  const after = effectiveLists(ACL_DATA, ACL_INHERITED);
  const users = new Set([
    ...ACL_BEFORE.allow_read, ...ACL_BEFORE.allow_write, ...ACL_BEFORE.deny_read,
    ...after.allow_read, ...after.allow_write, ...after.deny_read,
    ...ACL_OWN_BEFORE.allow_read, ...ACL_OWN_BEFORE.allow_write, ...ACL_OWN_BEFORE.deny_read,
    ...ACL_DATA.allow_read, ...ACL_DATA.allow_write, ...ACL_DATA.deny_read,
  ]);
  const changes = [];
  for (const user of users) {
    const beforeAllow = ACL_BEFORE.allow_read.includes(user) || ACL_BEFORE.allow_write.includes(user);
    const afterAllow = after.allow_read.includes(user) || after.allow_write.includes(user);
    const beforeDeny = ACL_BEFORE.deny_read.includes(user);
    const afterDeny = after.deny_read.includes(user);
    const ownBeforeAllow = ACL_OWN_BEFORE.allow_read.includes(user) || ACL_OWN_BEFORE.allow_write.includes(user);
    const ownAfterAllow = ACL_DATA.allow_read.includes(user) || ACL_DATA.allow_write.includes(user);
    const ownBeforeDeny = ACL_OWN_BEFORE.deny_read.includes(user);
    const ownAfterDeny = ACL_DATA.deny_read.includes(user);
    const kinds = [];
    if (!beforeAllow && afterAllow) kinds.push("add allow");
    if (!beforeDeny && afterDeny) kinds.push("add deny (also revokes write)");
    if (ownBeforeAllow && !ownAfterAllow) kinds.push("remove allow (fall back to inheritance)");
    if (ownBeforeDeny && !ownAfterDeny) kinds.push("remove deny (fall back to inheritance)");
    if (kinds.length === 0) continue;
    changes.push({
      user,
      before: aclPermOf(ACL_BEFORE, user),
      after: aclPermOf(after, user),
      kinds,
    });
  }
  return changes;
}

function showAclDiff(changes, tftpChanged) {
  const $diff = document.getElementById("aclDiffModal");
  const lines = [`Path: ${ACL_PATH}`];
  if (tftpChanged) {
    lines.push("");
    lines.push(`TFTP: ${ACL_TFTP ? "enabled" : "disabled"} (was ${ACL_TFTP_BEFORE ? "enabled" : "disabled"})`);
  }
  for (const change of changes) {
    lines.push("");
    lines.push(`${change.user}: current ${change.before} -> target ${change.after}`);
    for (const kind of change.kinds) lines.push(`  ${kind}`);
  }
  if (ACL_CHAIN.length > 0) {
    lines.push("");
    lines.push("Rule chain:");
    for (const entry of ACL_CHAIN) {
      const [path, rule] = entry;
      const parts = [];
      if (rule.allow_read) parts.push(`allow_read: ${rule.allow_read.join(", ") || "(empty)"}`);
      if (rule.allow_write) parts.push(`allow_write: ${rule.allow_write.join(", ") || "(empty)"}`);
      if (rule.deny_read) parts.push(`deny_read: ${rule.deny_read.join(", ") || "(empty)"}`);
      lines.push(`  ${path}  ${parts.join("  ")}`);
    }
  }
  $diff.querySelector(".acl-diff-body").textContent = lines.join("\n");
  $diff.querySelector(".modal-status").textContent = "";
  $diff.classList.remove("hidden");
}

async function saveWhitelist() {
  normalizeAclLists();
  const changes = aclChanges();
  const tftpChanged = ACL_TFTP !== ACL_TFTP_BEFORE;
  if (changes.length > 0 || tftpChanged) {
    showAclDiff(changes, tftpChanged);
    return;
  }
  await putAcl();
}

async function putAcl() {
  const $modal = document.getElementById("whitelistModal");
  const $status = $modal.querySelector(".modal-status");
  const $diff = document.getElementById("aclDiffModal");
  const $diffStatus = $diff.querySelector(".modal-status");
  const ips = parseWhitelistInput($modal.querySelector(".whitelist-input").value);
  const tftpChanged = ACL_TFTP !== ACL_TFTP_BEFORE;
  const ipChanged = JSON.stringify(ips) !== JSON.stringify(ACL_IPS_BEFORE);
  // A path without a user rule must stay without one when only the tftp
  // switch is edited; sending empty lists would turn it into "deny everyone".
  // An existing own rule is always sent back unchanged.
  const omitLists = tftpChanged
    && aclChanges().length === 0
    && ACL_OWN_NULL.allow_read
    && ACL_OWN_NULL.allow_write
    && ACL_OWN_NULL.deny_read;
  $status.textContent = "Saving...";
  $diffStatus.textContent = "Saving...";
  try {
    const payload = {
      version: ACL_VERSION,
    };
    if (!omitLists) {
      payload.allow_read = ACL_DATA.allow_read;
      payload.allow_write = ACL_DATA.allow_write;
      payload.deny_read = ACL_DATA.deny_read;
    }
    if (!omitLists || ipChanged) {
      payload.ips = ips;
    }
    if (tftpChanged) {
      payload.enable_tftp = ACL_TFTP;
    }
    const res = await fetch(aclUrl(ACL_PATH), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    await assertResOK(res);
    $status.textContent = "Saved";
    $modal.classList.add("hidden");
    $diff.classList.add("hidden");
    await refreshPage();
  } catch (err) {
    $status.textContent = "";
    $diffStatus.textContent = "";
    if (String(err.message).includes("modified") || String(err.message).includes("409")) {
      alert("ACL has been modified by another user. Reload and try again.");
    } else {
      alert(`Failed to save acl, ${err.message}`);
    }
  }
}

async function confirmAclSave() {
  await putAcl();
}

async function removeWhitelist() {
  const $modal = document.getElementById("whitelistModal");
  const $status = $modal.querySelector(".modal-status");
  $status.textContent = "Saving...";
  try {
    const url = aclUrl(ACL_PATH) + (ACL_VERSION ? "&version=" + encodeURIComponent(ACL_VERSION) : "");
    const res = await fetch(url, { method: "DELETE" });
    await assertResOK(res);
    $status.textContent = "Saved";
    $modal.classList.add("hidden");
    await refreshPage();
  } catch (err) {
    $status.textContent = "";
    alert(`Failed to remove acl rule, ${err.message}`);
  }
}

function manageWhitelist(index) {
  const file = DATA.paths[index];
  if (!file) return;
  const base = DATA.href === "/" ? "/" : DATA.href + "/";
  openWhitelistModal(base + file.name);
}

/**
 * Wire the editor toolbar once. Content and visibility are re-applied by
 * renderEditor() on every navigation.
 */
function setupEditorPage() {
  const $moveFile = document.querySelector(".move-file");
  $moveFile.addEventListener("click", async () => {
    const url = baseUrl();
    const query = location.href.slice(url.length);
    const newFileUrl = await doMovePath(url);
    if (newFileUrl) {
      await navigateTo(newFileUrl + query);
    }
  });

  const $deleteFile = document.querySelector(".delete-file");
  $deleteFile.addEventListener("click", async () => {
    const url = baseUrl();
    const name = baseName(url);
    await doDeletePath(name, url, async () => {
      const parent = location.href.split(/[?#]/)[0].split("/").slice(0, -1).join("/");
      await navigateTo(parent || "/");
    });
  });

  const $saveBtn = document.querySelector(".save-btn");
  $saveBtn.addEventListener("click", saveChange);
}

/**
 * Show a short-lived status message.
 */
function showToast(message) {
  let $toast = document.getElementById("dufs-toast");
  if (!$toast) {
    $toast = document.createElement("div");
    $toast.id = "dufs-toast";
    document.body.appendChild($toast);
  }
  $toast.textContent = message;
  $toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => $toast.classList.remove("show"), 1600);
}

function applyEditorChrome(isEdit) {
  const $download = document.querySelector(".download");
  $download.classList.remove("hidden");
  $download.href = baseUrl();

  toggleControl(".move-file", isEdit);
  toggleControl(".delete-file", isEdit);
  toggleControl(".save-btn", isEdit && !!DATA.editable);
  toggleControl(".upload-file", false);
  toggleControl(".new-folder", false);
  toggleControl(".new-file", false);
  toggleControl(".ip-whitelist-btn", false);
  toggleControl(".searchbar", false);
}

/**
 * Render an Edit/View page from DATA.
 */
async function renderEditor() {
  const url = baseUrl();
  const isEdit = DATA.kind === "Edit";
  document.title = `${isEdit ? "Edit" : "View"} ${DATA.href} - Dufs`;

  applyEditorChrome(isEdit);

  const $notEditable = document.querySelector(".not-editable");
  $notEditable.classList.add("hidden");
  $notEditable.textContent = "";
  document.querySelectorAll(".editor-page iframe").forEach($el => $el.remove());
  $editor.readonly = !isEdit;
  $editor.classList.add("hidden");

  if (!DATA.editable) {
    const ext = extName(baseName(url));
    if (IFRAME_FORMATS.find(v => v === ext)) {
      $notEditable.insertAdjacentHTML("afterend", `<iframe src="${url}" sandbox width="100%" height="${window.innerHeight - 100}px"></iframe>`);
    } else {
      $notEditable.classList.remove("hidden");
      $notEditable.textContent = "Cannot edit because file is too large or binary.";
    }
    return;
  }

  $editor.classList.remove("hidden");
  try {
    const res = await fetch(url);
    await assertResOK(res);
    const encoding = getEncoding(res.headers.get("content-type"));
    if (encoding === "utf-8") {
      $editor.value = await res.text();
    } else {
      const bytes = await res.arrayBuffer();
      const dataView = new DataView(bytes);
      const decoder = new TextDecoder(encoding);
      $editor.value = decoder.decode(dataView);
    }
  } catch (err) {
    alert(`Failed to get file, ${err.message}`);
  }
}

/**
 * Swap the current page (index or editor) for another one without replacing
 * the document.
 */
async function applyPage(data, url, push) {
  DATA = data;
  PARAMS = Object.fromEntries(new URL(url, location.href).searchParams.entries());
  if (push) {
    history.pushState({ dufs: true }, "", url);
  }

  const $breadcrumb = document.querySelector(".breadcrumb");
  $breadcrumb.innerHTML = "";
  addBreadcrumb(data.href, data.uri_prefix);

  const isIndex = data.kind === "Index";
  document.querySelector(".index-page").classList.toggle("hidden", !isIndex);
  document.querySelector(".editor-page").classList.toggle("hidden", isIndex);
  if (isIndex) {
    $editor.classList.add("hidden");
    document.querySelectorAll(".editor-page iframe").forEach($el => $el.remove());
    document.querySelector(".not-editable").classList.add("hidden");
    renderIndex();
  } else {
    await renderEditor();
  }
  window.scrollTo(0, 0);
}

/**
 * Delete path
 * @param {number} index
 * @returns
 */
async function deletePath(index) {
  const file = DATA.paths[index];
  if (!file) return;
  await doDeletePath(file.name, newUrl(file.name), () => {
    document.getElementById(`addPath${index}`)?.remove();
    DATA.paths[index] = null;
    invalidateNavCache();
    if (!DATA.paths.find(v => !!v)) {
      $pathsTable.classList.add("hidden");
      $emptyFolder.textContent = DIR_EMPTY_NOTE;
      $emptyFolder.classList.remove("hidden");
    }
  });
}

async function doDeletePath(name, url, cb) {
  if (!confirm(`Delete \`${name}\`?`)) return;
  try {
    await checkAuth();
    const res = await fetch(url, {
      method: "DELETE",
    });
    await assertResOK(res);
    invalidateNavCache();
    cb();
  } catch (err) {
    alert(`Cannot delete \`${file.name}\`, ${err.message}`);
  }
}

/**
 * Move path
 * @param {number} index
 * @returns
 */
async function movePath(index) {
  const file = DATA.paths[index];
  if (!file) return;
  const fileUrl = newUrl(file.name);
  const newFileUrl = await doMovePath(fileUrl);
  if (newFileUrl) {
    await navigateTo(newFileUrl.split("/").slice(0, -1).join("/"));
  }
}

async function doMovePath(fileUrl) {
  const fileUrlObj = new URL(fileUrl);

  const prefix = DATA.uri_prefix.slice(0, -1);

  const filePath = decodeURIComponent(fileUrlObj.pathname.slice(prefix.length));

  let newPath = prompt("Enter new path", filePath);
  if (!newPath) return;
  if (!newPath.startsWith("/")) newPath = "/" + newPath;
  if (filePath === newPath) return;
  const newFileUrl = fileUrlObj.origin + prefix + newPath.split("/").map(encodeURIComponent).join("/");

  try {
    await checkAuth();
    const res1 = await fetch(newFileUrl, {
      method: "HEAD",
    });
    if (res1.status === 200) {
      if (!confirm("Override existing file?")) {
        return;
      }
    }
    const res2 = await fetch(fileUrl, {
      method: "MOVE",
      headers: {
        "Destination": newFileUrl,
      }
    });
    await assertResOK(res2);
    invalidateNavCache();
    return newFileUrl;
  } catch (err) {
    alert(`Cannot move \`${filePath}\` to \`${newPath}\`, ${err.message}`);
  }
}


/**
 * Save editor change
 */
async function saveChange() {
  try {
    const res = await fetch(baseUrl(), {
      method: "PUT",
      body: $editor.value,
    });
    await assertResOK(res);
    invalidateNavCache();
    showToast("Saved");
  } catch (err) {
    alert(`Failed to save file, ${err.message}`);
  }
}

async function checkAuth(variant) {
  if (!DATA.auth) return;
  const qs = variant ? `?${variant}` : "";
  const res = await fetch(baseUrl() + qs, {
    method: "CHECKAUTH",
  });
  await assertResOK(res);
  $loginBtn.classList.add("hidden");
  $logoutBtn.classList.remove("hidden");
  $userName.textContent = await res.text();
}

function logout() {
  if (!DATA.auth) return;
  if (DATA.auth_type === "oidc") {
    location.href = `${DATA.uri_prefix}__dufs__/oidc/logout`;
    return;
  }
  const url = baseUrl();
  const xhr = new XMLHttpRequest();
  xhr.open("LOGOUT", url, true, DATA.user);
  xhr.onload = () => {
    location.href = url;
  }
  xhr.send();
}

/**
 * Create a folder
 * @param {string} name
 */
async function createFolder(name) {
  const url = newUrl(name);
  try {
    await checkAuth();
    const res = await fetch(url, {
      method: "MKCOL",
    });
    await assertResOK(res);
    invalidateNavCache();
    await navigateTo(url.endsWith("/") ? url : url + "/");
  } catch (err) {
    alert(`Cannot create folder \`${name}\`, ${err.message}`);
  }
}

async function createFile(name) {
  const url = newUrl(name);
  try {
    await checkAuth();
    const res = await fetch(url, {
      method: "PUT",
      body: "",
    });
    await assertResOK(res);
    invalidateNavCache();
    await navigateTo(url + "?edit");
  } catch (err) {
    alert(`Cannot create file \`${name}\`, ${err.message}`);
  }
}

async function addFileEntries(entries, dirs) {
  for (const entry of entries) {
    if (entry.isFile) {
      entry.file(file => {
        new Uploader(file, dirs).upload();
      });
    } else if (entry.isDirectory) {
      const dirReader = entry.createReader();

      const successCallback = entries => {
        if (entries.length > 0) {
          addFileEntries(entries, [...dirs, entry.name]);
          dirReader.readEntries(successCallback);
        }
      };

      dirReader.readEntries(successCallback);
    }
  }
}


function newUrl(name) {
  let url = baseUrl();
  if (!url.endsWith("/")) url += "/";
  url += name.split("/").map(encodeURIComponent).join("/");
  return url;
}

function baseUrl() {
  return location.href.split(/[?#]/)[0];
}

function baseName(url) {
  return decodeURIComponent(url.split("/").filter(v => v.length > 0).slice(-1)[0]);
}

function extName(filename) {
  const dotIndex = filename.lastIndexOf('.');

  if (dotIndex === -1 || dotIndex === 0 || dotIndex === filename.length - 1) {
    return '';
  }

  return filename.substring(dotIndex);
}

function getPathSvg(path_type) {
  switch (path_type) {
    case "Dir":
      return iconSvg("dir");
    case "SymlinkFile":
      return iconSvg("symlinkFile");
    case "SymlinkDir":
      return iconSvg("symlinkDir");
    default:
      return iconSvg("file");
  }
}

function formatMtime(mtime) {
  if (!mtime) return "";
  const date = new Date(mtime);
  const year = date.getFullYear();
  const month = padZero(date.getMonth() + 1, 2);
  const day = padZero(date.getDate(), 2);
  const hours = padZero(date.getHours(), 2);
  const minutes = padZero(date.getMinutes(), 2);
  return `${year}-${month}-${day} ${hours}:${minutes}`;
}

function padZero(value, size) {
  return ("0".repeat(size) + value).slice(-1 * size);
}

function formatDirSize(size) {
  const unit = size === 1 ? "item" : "items";
  const num = size >= MAX_SUBPATHS_COUNT ? `>${MAX_SUBPATHS_COUNT - 1}` : `${size}`;
  return ` ${num} ${unit}`;
}

function formatFileSize(size, unit) {
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.max(0, unit ? sizes.indexOf(unit) : (size > 0 ? parseInt(Math.floor(Math.log(size) / Math.log(1024))) : 0));
  const raw = size > 0 ? size / Math.pow(1024, i) : 0;
  if (i === 0) return [Math.round(raw), "B"];
  return [raw.toFixed(1), sizes[i]];
}

function formatDuration(seconds) {
  if (!isFinite(seconds) || seconds <= 0) return "--:--";
  seconds = Math.ceil(seconds);
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds - h * 3600) / 60);
  const s = seconds - h * 3600 - m * 60;
  if (h > 0) return `${padZero(h, 2)}:${padZero(m, 2)}:${padZero(s, 2)}`;
  return `${padZero(m, 2)}:${padZero(s, 2)}`;
}

function formatUploadSize(uploaded, total) {
  const unit = formatFileSize(total)[1];
  const [uploadedValue] = formatFileSize(uploaded, unit);
  const [totalValue] = formatFileSize(total, unit);
  return `${uploadedValue}/${totalValue} ${unit}`;
}

function formatPercent(percent) {
  return Math.round(percent) + "%";
}

function encodedStr(rawStr) {
  return rawStr.replace(/[\u00A0-\u9999<>\&]/g, function (i) {
    return '&#' + i.charCodeAt(0) + ';';
  });
}

async function assertResOK(res) {
  if (!(res.status >= 200 && res.status < 300)) {
    throw new Error(await res.text() || `Invalid status ${res.status}`);
  }
}

function getEncoding(contentType) {
  const charset = contentType?.split(";")[1];
  if (/charset/i.test(charset)) {
    let encoding = charset.split("=")[1];
    if (encoding) {
      return encoding.toLowerCase();
    }
  }
  return 'utf-8';
}

// Parsing base64 strings with Unicode characters
function decodeBase64(base64String) {
  const binString = atob(base64String);
  const len = binString.length;
  const bytes = new Uint8Array(len);
  const arr = new Uint32Array(bytes.buffer, 0, Math.floor(len / 4));
  let i = 0;
  for (; i < arr.length; i++) {
    arr[i] = binString.charCodeAt(i * 4) |
      (binString.charCodeAt(i * 4 + 1) << 8) |
      (binString.charCodeAt(i * 4 + 2) << 16) |
      (binString.charCodeAt(i * 4 + 3) << 24);
  }
  for (i = i * 4; i < len; i++) {
    bytes[i] = binString.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}
