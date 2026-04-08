const CHANNELS = ["cli", "ant"];
const CHANNEL_META = {
    cli: { label: "CLI" },
    ant: { label: "ANT" },
};
const REFRESH_INTERVAL_MS = 15000;
const WHITELIST_VALIDATE_DEBOUNCE_MS = 700;
const WHITELIST_DEFAULT_MESSAGE = "输入后会自动校验目标服务器里是否存在该文件。";
const STATUS_LABELS = {
    ok: "成功",
    warning: "警告",
    error: "失败",
    partial: "部分成功",
};
const TRIGGER_LABELS = {
    startup: "启动",
    scheduled: "定时",
    manual: "手动",
};
const EVENT_TYPE_LABELS = {
    scan: "扫描",
    action: "动作",
};

let isConfigDirty = false;
let flashHideTimer = null;
let whitelistValidationTimer = null;
let whitelistValidationRequestSeq = 0;

async function apiFetch(path, options = {}) {
    const response = await fetch(path, {
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {}),
        },
        ...options,
    });

    let payload = {};
    try {
        payload = await response.json();
    } catch (error) {
        payload = {};
    }

    if (response.status === 401) {
        window.location.replace("/login");
        throw new Error(payload.detail || "未登录或会话已过期，请重新登录。");
    }

    if (!response.ok) {
        const message = payload.detail || payload.message || `请求失败：${response.status}`;
        throw new Error(message);
    }
    return payload;
}

function formatTimestamp(value) {
    if (!value) {
        return "-";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }
    return date.toLocaleString("zh-CN", { hour12: false });
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function formatBoolean(value) {
    return value ? "是" : "否";
}

function formatStatus(value) {
    return STATUS_LABELS[value] || value || "-";
}

function formatTrigger(value) {
    return TRIGGER_LABELS[value] || value || "-";
}

function formatEventType(value) {
    return EVENT_TYPE_LABELS[value] || value || "-";
}

function statusTone(status) {
    if (status === "ok") {
        return "success";
    }
    if (status === "partial" || status === "warning") {
        return "warning";
    }
    if (status === "error") {
        return "error";
    }
    return "neutral";
}

function whitelistFromTextarea(channel) {
    return document
        .getElementById(`channel-whitelist-${channel}`)
        .value.split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean);
}

function setTextareaValidationTone(channel, tone = "neutral") {
    const textarea = document.getElementById(`channel-whitelist-${channel}`);
    if (!textarea) {
        return;
    }
    if (!tone || tone === "neutral") {
        delete textarea.dataset.validationTone;
        return;
    }
    textarea.dataset.validationTone = tone;
}

function setWhitelistValidationMessage(channel, message, tone = "neutral") {
    const element = document.getElementById(`channel-whitelist-validation-${channel}`);
    if (element) {
        element.textContent = message;
        element.dataset.tone = tone;
    }
    setTextareaValidationTone(channel, tone);
}

function resetWhitelistValidationMessage(channel) {
    const whitelist = whitelistFromTextarea(channel);
    if (!whitelist.length) {
        setWhitelistValidationMessage(channel, "未填写白名单。", "neutral");
        return;
    }
    setWhitelistValidationMessage(channel, WHITELIST_DEFAULT_MESSAGE, "neutral");
}

function resetAllWhitelistValidationMessages() {
    CHANNELS.forEach((channel) => {
        resetWhitelistValidationMessage(channel);
    });
}

function renderWhitelistValidationResult(channel, result) {
    const whitelist = whitelistFromTextarea(channel);
    if (!whitelist.length) {
        resetWhitelistValidationMessage(channel);
        return;
    }
    if (!result) {
        setWhitelistValidationMessage(channel, WHITELIST_DEFAULT_MESSAGE, "neutral");
        return;
    }
    if (!result.checked) {
        setWhitelistValidationMessage(channel, result.message || WHITELIST_DEFAULT_MESSAGE, "neutral");
        return;
    }
    if (result.valid) {
        setWhitelistValidationMessage(channel, result.message || `已校验，通过 ${whitelist.length} 个文件。`, "success");
        return;
    }
    setWhitelistValidationMessage(channel, result.message || "存在未通过校验的白名单文件。", "error");
}

function setElementText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function readConfigForm() {
    return {
        target_base_url: document.getElementById("target-base-url").value.trim(),
        panel_password: document.getElementById("panel-password").value,
        poll_interval_seconds: Number(document.getElementById("poll-interval-seconds").value || 60),
        request_timeout_seconds: Number(document.getElementById("request-timeout-seconds").value || 10),
        enable_batch_size: Number(document.getElementById("enable-batch-size").value || 1),
        channels: Object.fromEntries(
            CHANNELS.map((channel) => [
                channel,
                {
                    enabled: document.getElementById(`channel-enabled-${channel}`).checked,
                    whitelist: whitelistFromTextarea(channel),
                },
            ]),
        ),
    };
}

function clearAccessPasswordForm() {
    [
        "current-access-password",
        "new-access-password",
        "confirm-access-password",
    ].forEach((id) => {
        const element = document.getElementById(id);
        if (element) {
            element.value = "";
        }
    });
}

function updateConfigStateIndicator() {
    const pill = document.getElementById("config-pill");
    if (!pill) {
        return;
    }

    if (isConfigDirty) {
        pill.dataset.state = "dirty";
        setElementText("config-dirty-indicator", "有未保存更改");
        return;
    }

    pill.dataset.state = "clean";
    setElementText("config-dirty-indicator", "已同步");
}

function markConfigDirty() {
    isConfigDirty = true;
    updateConfigStateIndicator();
}

function applyConfig(config, options = {}) {
    const { markClean = true } = options;

    document.getElementById("target-base-url").value = config.target_base_url || "";
    document.getElementById("panel-password").value = config.panel_password || "";
    document.getElementById("poll-interval-seconds").value = config.poll_interval_seconds ?? 60;
    document.getElementById("request-timeout-seconds").value = config.request_timeout_seconds ?? 10;
    document.getElementById("enable-batch-size").value = config.enable_batch_size ?? 1;

    CHANNELS.forEach((channel) => {
        const settings = config.channels?.[channel] || { enabled: true, whitelist: [] };
        document.getElementById(`channel-enabled-${channel}`).checked = Boolean(settings.enabled);
        document.getElementById(`channel-whitelist-${channel}`).value = (settings.whitelist || []).join("\n");
    });

    whitelistValidationRequestSeq += 1;
    resetAllWhitelistValidationMessages();
    isConfigDirty = !markClean;
    updateConfigStateIndicator();
}

function showFlash(message, tone = "info") {
    const flash = document.getElementById("flash");
    if (!flash) {
        return;
    }

    flash.textContent = message;
    flash.dataset.tone = tone;
    flash.classList.add("is-visible");

    if (flashHideTimer) {
        clearTimeout(flashHideTimer);
    }
    flashHideTimer = window.setTimeout(() => {
        flash.classList.remove("is-visible");
    }, 4200);
}

function setConnectionTestResult(message, tone = "neutral") {
    const element = document.getElementById("connection-test-result");
    if (!element) {
        return;
    }
    element.textContent = message;
    element.dataset.tone = tone;
}

async function runWhitelistValidation(options = {}) {
    const { silent = true } = options;
    const payload = readConfigForm();
    const hasWhitelist = CHANNELS.some((channel) => payload.channels[channel].whitelist.length > 0);
    if (!hasWhitelist) {
        resetAllWhitelistValidationMessages();
        return null;
    }

    if (!payload.target_base_url || !payload.panel_password) {
        CHANNELS.forEach((channel) => {
            if (payload.channels[channel].whitelist.length) {
                setWhitelistValidationMessage(channel, "请先填写目标服务地址和面板密码，才能校验白名单。", "warning");
                return;
            }
            resetWhitelistValidationMessage(channel);
        });
        return null;
    }

    const requestSeq = ++whitelistValidationRequestSeq;
    CHANNELS.forEach((channel) => {
        if (payload.channels[channel].whitelist.length) {
            setWhitelistValidationMessage(channel, "正在校验目标服务器中的文件名...", "neutral");
            return;
        }
        resetWhitelistValidationMessage(channel);
    });

    try {
        const result = await apiFetch("/api/validate-whitelists", {
            method: "POST",
            body: JSON.stringify(payload),
        });
        if (requestSeq !== whitelistValidationRequestSeq) {
            return result;
        }

        CHANNELS.forEach((channel) => {
            renderWhitelistValidationResult(channel, result.channels?.[channel]);
        });
        return result;
    } catch (error) {
        if (requestSeq !== whitelistValidationRequestSeq) {
            return null;
        }

        CHANNELS.forEach((channel) => {
            if (payload.channels[channel].whitelist.length) {
                setWhitelistValidationMessage(channel, error.message, "error");
                return;
            }
            resetWhitelistValidationMessage(channel);
        });

        if (!silent) {
            showFlash(error.message, "error");
        }
        throw error;
    }
}

function scheduleWhitelistValidation() {
    whitelistValidationRequestSeq += 1;
    if (whitelistValidationTimer) {
        clearTimeout(whitelistValidationTimer);
    }
    whitelistValidationTimer = window.setTimeout(() => {
        runWhitelistValidation().catch(() => {});
    }, WHITELIST_VALIDATE_DEBOUNCE_MS);
}

function renderSchedulerState(runtime) {
    const pill = document.getElementById("scheduler-pill");
    if (!pill) {
        return;
    }
    pill.dataset.state = runtime.scheduler_running ? "running" : "idle";
    setElementText("scheduler-running", runtime.scheduler_running ? "运行中" : "已停止");
}

function deriveChannelHealth(state) {
    if (!state?.enabled) {
        return { label: "已关闭", tone: "disabled" };
    }
    if (state?.last_scan_status === "error") {
        return { label: "扫描失败", tone: "error" };
    }
    if ((state?.stats?.normal ?? 0) > 0) {
        return { label: "运行正常", tone: "healthy" };
    }
    if ((state?.stats?.normal ?? 0) === 0 && state?.last_scan_at) {
        return { label: "等待补位", tone: "warning" };
    }
    return { label: "待检查", tone: "unknown" };
}

function renderOverview(runtime) {
    let totalNormal = 0;
    let enabledChannels = 0;
    let alertChannels = 0;
    let whitelistTotal = 0;

    CHANNELS.forEach((channel) => {
        const state = runtime.channels?.[channel];
        if (!state) {
            return;
        }

        totalNormal += Number(state.stats?.normal || 0);
        whitelistTotal += Array.isArray(state.whitelist) ? state.whitelist.length : 0;
        if (state.enabled) {
            enabledChannels += 1;
        }
        if (state.last_scan_status === "error" || (state.last_scan_at && Number(state.stats?.normal || 0) === 0)) {
            alertChannels += 1;
        }
    });

    setElementText("summary-normal-total", String(totalNormal));
    setElementText("summary-alert-channels", String(alertChannels));
    setElementText("summary-enabled-channels", String(enabledChannels));
    setElementText("summary-whitelist-total", String(whitelistTotal));
}

function renderChannelState(channel, state) {
    if (!isConfigDirty) {
        const enabledElement = document.getElementById(`channel-enabled-${channel}`);
        const whitelistElement = document.getElementById(`channel-whitelist-${channel}`);
        if (enabledElement) {
            enabledElement.checked = Boolean(state.enabled);
        }
        if (whitelistElement) {
            whitelistElement.value = (state.whitelist || []).join("\n");
        }
    }

    setElementText(`channel-total-${channel}`, String(state.stats?.total ?? 0));
    setElementText(`channel-normal-${channel}`, String(state.stats?.normal ?? 0));
    setElementText(`channel-disabled-${channel}`, String(state.stats?.disabled ?? 0));
    setElementText(`channel-whitelist-count-${channel}`, String((state.whitelist || []).length));
    setElementText(`channel-last-scan-${channel}`, formatTimestamp(state.last_scan_at));
    setElementText(`channel-last-scan-message-${channel}`, state.last_scan_message || "-");
    setElementText(
        `channel-last-action-${channel}`,
        state.last_action_at
            ? `${formatTimestamp(state.last_action_at)} | ${state.last_action_message || "-"}`
            : (state.last_action_message || "-"),
    );

    const health = deriveChannelHealth(state);
    const healthElement = document.getElementById(`channel-health-${channel}`);
    if (healthElement) {
        healthElement.textContent = health.label;
        healthElement.dataset.state = health.tone;
    }

    const card = document.querySelector(`[data-channel-card='${channel}']`);
    if (card) {
        card.dataset.state = health.tone;
    }
}

function renderRuntime(runtime) {
    renderSchedulerState(runtime);
    setElementText("last-scan-at", formatTimestamp(runtime.last_cycle_finished_at));
    setElementText("next-scan-at", formatTimestamp(runtime.next_scheduled_at));
    setElementText("runtime-configured", formatBoolean(runtime.configured));
    setElementText("runtime-in-progress", formatBoolean(runtime.scan_in_progress));
    setElementText("runtime-last-error", runtime.last_error || "-");

    CHANNELS.forEach((channel) => {
        const state = runtime.channels?.[channel];
        if (state) {
            renderChannelState(channel, state);
        }
    });

    renderOverview(runtime);
}

function renderStatusBadge(status) {
    return `<span class="status-tag" data-tone="${escapeHtml(statusTone(status))}">${escapeHtml(formatStatus(status))}</span>`;
}

function buildHistorySummary(item) {
    if (item.event_type === "scan") {
        return `统计 ${item.total ?? 0}/${item.normal ?? 0}/${item.disabled ?? 0} | 动作 ${formatBoolean(item.action_taken)}`;
    }

    const requestedCount = Array.isArray(item.requested_filenames) ? item.requested_filenames.length : 0;
    const successCount = Number(item.success_count ?? (item.successful_filenames || []).length);
    const failureCount = Number(item.failure_count ?? (item.failed_filenames || []).length);
    return `请求 ${requestedCount} | 成功 ${successCount} | 失败 ${failureCount}`;
}

function renderHistory(items) {
    const body = document.getElementById("history-body");
    body.innerHTML = "";

    if (!items.length) {
        body.innerHTML = '<tr><td colspan="7">暂无历史记录。</td></tr>';
        return;
    }

    items.forEach((item) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${escapeHtml(formatTimestamp(item.occurred_at))}</td>
            <td>${escapeHtml(formatEventType(item.event_type))}</td>
            <td>${escapeHtml(CHANNEL_META[item.channel]?.label || item.channel)}</td>
            <td>${escapeHtml(formatTrigger(item.trigger_type))}</td>
            <td>${renderStatusBadge(item.status)}</td>
            <td class="message-cell" title="${escapeHtml(buildHistorySummary(item))}">${escapeHtml(buildHistorySummary(item))}</td>
            <td class="message-cell" title="${escapeHtml(item.message || "-")}">${escapeHtml(item.message || "-")}</td>
        `;
        body.appendChild(row);
    });
}

async function loadConfig(force = false) {
    if (isConfigDirty && !force) {
        return;
    }
    const config = await apiFetch("/api/config");
    applyConfig(config);
}

async function loadRuntime() {
    const runtime = await apiFetch("/api/runtime-status");
    renderRuntime(runtime);
}

async function loadHistories() {
    const history = await apiFetch("/api/history?limit=60");
    renderHistory(history.items || []);
}

async function refreshAll(options = {}) {
    const includeConfig = Boolean(options.includeConfig);
    try {
        const tasks = [loadRuntime(), loadHistories()];
        if (includeConfig) {
            tasks.unshift(loadConfig(true));
        }
        await Promise.all(tasks);
    } catch (error) {
        showFlash(error.message, "error");
    }
}

async function saveConfiguration() {
    try {
        await apiFetch("/api/config", {
            method: "POST",
            body: JSON.stringify(readConfigForm()),
        });
        showFlash("配置已保存到本地数据库。", "success");
        isConfigDirty = false;
        updateConfigStateIndicator();
        await refreshAll({ includeConfig: true });
        await runWhitelistValidation().catch(() => {});
    } catch (error) {
        await runWhitelistValidation().catch(() => {});
        showFlash(error.message, "error");
        throw error;
    }
}

async function changeAccessPassword() {
    const payload = {
        current_password: document.getElementById("current-access-password").value,
        new_password: document.getElementById("new-access-password").value,
        confirm_password: document.getElementById("confirm-access-password").value,
    };
    const result = await apiFetch("/api/access-password", {
        method: "POST",
        body: JSON.stringify(payload),
    });
    clearAccessPasswordForm();
    showFlash(result.message || "访问密码已修改。", "success");
}

async function logout() {
    try {
        await apiFetch("/auth/logout", {
            method: "POST",
            body: JSON.stringify({}),
        });
    } catch (error) {
        // Even if logout request fails, redirect to login to clear the local UI state.
    }
    window.location.replace("/login");
}

async function testConnection() {
    const payload = readConfigForm();
    try {
        const result = await apiFetch("/api/test-connection", {
            method: "POST",
            body: JSON.stringify({
                target_base_url: payload.target_base_url,
                panel_password: payload.panel_password,
                request_timeout_seconds: payload.request_timeout_seconds,
            }),
        });
        const summary = CHANNELS.map((channel) => {
            const stats = result.channels?.[channel] || {};
            return `${CHANNEL_META[channel]?.label || channel}：总数 ${stats.total ?? 0}，正常 ${stats.normal ?? 0}，禁用 ${stats.disabled ?? 0}`;
        }).join("；");
        setConnectionTestResult(summary, "success");
        await runWhitelistValidation().catch(() => {});
        showFlash("连接测试成功。", "success");
    } catch (error) {
        setConnectionTestResult(error.message, "error");
        showFlash(error.message, "error");
        throw error;
    }
}

async function triggerScan(channel = null) {
    const path = channel ? `/api/scan-now/${channel}` : "/api/scan-now";
    const result = await apiFetch(path, {
        method: "POST",
    });
    showFlash(result.message || "扫描完成。", result.ok ? "success" : "error");
    await Promise.all([loadRuntime(), loadHistories()]);
}

function bindAsyncButton(button, action, busyLabel) {
    if (!button) {
        return;
    }

    const originalLabel = button.textContent;
    button.addEventListener("click", async () => {
        if (button.disabled) {
            return;
        }
        button.disabled = true;
        button.dataset.busy = "true";
        button.textContent = busyLabel;
        try {
            await action();
        } catch (error) {
            if (!(error instanceof Error)) {
                showFlash("发生未知错误。", "error");
            }
        } finally {
            button.disabled = false;
            button.textContent = originalLabel;
            delete button.dataset.busy;
        }
    });
}

function bindConfigFields() {
    document.querySelectorAll("[data-config-field='true']").forEach((element) => {
        const shouldValidateWhitelist =
            element.dataset.whitelistField === "true"
            || ["target-base-url", "panel-password", "request-timeout-seconds"].includes(element.id);
        const handler = shouldValidateWhitelist ? () => {
            markConfigDirty();
            scheduleWhitelistValidation();
        } : markConfigDirty;
        element.addEventListener("input", handler);
        element.addEventListener("change", handler);
    });
}

function bindEvents() {
    bindConfigFields();

    bindAsyncButton(document.getElementById("save-config-btn"), saveConfiguration, "正在保存...");
    bindAsyncButton(document.getElementById("test-connection-btn"), testConnection, "正在测试...");
    bindAsyncButton(document.getElementById("scan-now-btn"), () => triggerScan(), "正在扫描...");
    bindAsyncButton(document.getElementById("change-access-password-btn"), changeAccessPassword, "正在修改...");
    bindAsyncButton(document.getElementById("logout-btn"), logout, "退出中...");

    document.querySelectorAll(".scan-channel-btn").forEach((button) => {
        bindAsyncButton(button, () => triggerScan(button.dataset.channel), "扫描中...");
    });
}

document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    updateConfigStateIndicator();
    await refreshAll({ includeConfig: true });
    await runWhitelistValidation().catch(() => {});
    window.setInterval(async () => {
        try {
            await Promise.all([loadRuntime(), loadHistories()]);
        } catch (error) {
            showFlash(error.message, "error");
        }
    }, REFRESH_INTERVAL_MS);
});
