async function authFetch(path, payload) {
    const response = await fetch(path, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
    });

    let data = {};
    try {
        data = await response.json();
    } catch (error) {
        data = {};
    }

    if (!response.ok) {
        throw new Error(data.detail || data.message || `请求失败：${response.status}`);
    }
    return data;
}

function setMessage(message, tone = "neutral") {
    const element = document.getElementById("auth-message");
    element.textContent = message;
    element.dataset.tone = tone;
}

async function handleAuthSubmit(event) {
    event.preventDefault();
    const configured = Boolean(window.GUARDIAN_AUTH_PAGE?.passwordConfigured);
    const button = event.submitter || document.querySelector("#auth-form button[type='submit']");
    const originalLabel = button?.textContent || "";

    if (button) {
        button.disabled = true;
        button.textContent = configured ? "登录中..." : "设置中...";
    }

    try {
        if (configured) {
            const password = document.getElementById("login-password").value;
            await authFetch("/auth/login", { password });
            window.location.replace("/");
            return;
        }

        const password = document.getElementById("setup-password").value;
        const confirmPassword = document.getElementById("setup-confirm-password").value;
        await authFetch("/auth/setup", {
            password,
            confirm_password: confirmPassword,
        });
        window.location.replace("/");
    } catch (error) {
        setMessage(error.message, "error");
    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = originalLabel;
        }
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const configured = Boolean(window.GUARDIAN_AUTH_PAGE?.passwordConfigured);
    const preferredInputId = configured ? "login-password" : "setup-password";
    document.getElementById(preferredInputId)?.focus();
    document.getElementById("auth-form").addEventListener("submit", handleAuthSubmit);
});
