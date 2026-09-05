const API = {
    login: "/auth/login",
    logs: "/me/email-logs",
    quarantine: "/me/quarantine",
    scan: "/scan-email/"
};

let emailLogs = [];
let quarantineRecords = [];


/* -------------------------
   AUTH
-------------------------- */

function getToken() {
    return localStorage.getItem("swifpass_token");
}

function authHeaders() {
    const token = getToken();

    return token
        ? { Authorization: `Bearer ${token}` }
        : {};
}


async function login(email, password) {

    /*
       Try normal JSON login first.
       If the FastAPI endpoint expects OAuth-style form fields,
       automatically try that next.
    */

    let response = await fetch(API.login, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            email,
            password
        })
    });


    if (!response.ok) {

        const form = new URLSearchParams();

        form.append("username", email);
        form.append("email", email);
        form.append("password", password);

        response = await fetch(API.login, {
            method: "POST",
            headers: {
                "Content-Type":
                    "application/x-www-form-urlencoded"
            },
            body: form
        });
    }


    if (!response.ok) {
        throw new Error("Invalid email or password");
    }


    const data = await response.json();

    const token =
        data.access_token ||
        data.token ||
        data.jwt ||
        data.accessToken;


    if (!token) {
        throw new Error(
            "Login succeeded but no access token was returned."
        );
    }


    localStorage.setItem(
        "swifpass_token",
        token
    );


    localStorage.setItem(
        "swifpass_email",
        email
    );


    return data;
}


document
    .getElementById("loginForm")
    .addEventListener(
        "submit",
        async (event) => {

            event.preventDefault();

            const error =
                document.getElementById(
                    "loginError"
                );

            error.textContent = "";


            const email =
                document.getElementById(
                    "email"
                ).value.trim();


            const password =
                document.getElementById(
                    "password"
                ).value;


            try {

                await login(
                    email,
                    password
                );


                document
                    .getElementById(
                        "loginOverlay"
                    )
                    .classList
                    .add("hidden");


                document
                    .getElementById(
                        "tenantName"
                    )
                    .textContent =
                    "Security Administrator";


                await loadDashboardData();

            }

            catch (err) {

                error.textContent =
                    err.message;

            }

        }
    );


document
    .getElementById("logoutButton")
    .addEventListener(
        "click",
        () => {

            localStorage.removeItem(
                "swifpass_token"
            );

            localStorage.removeItem(
                "swifpass_email"
            );

            location.reload();

        }
    );


/* -------------------------
   API HELPERS
-------------------------- */

async function authenticatedFetch(
    url,
    options = {}
) {

    const headers = {
        ...authHeaders(),
        ...(options.headers || {})
    };


    const response =
        await fetch(
            url,
            {
                ...options,
                headers
            }
        );


    if (response.status === 401) {

        localStorage.removeItem(
            "swifpass_token"
        );

        document
            .getElementById(
                "loginOverlay"
            )
            .classList
            .remove("hidden");


        throw new Error(
            "Session expired"
        );

    }


    return response;
}


/* -------------------------
   DATA NORMALIZATION
-------------------------- */

function normalizeArray(data) {

    if (Array.isArray(data))
        return data;


    if (!data)
        return [];


    const possibleKeys = [
        "email_logs",
        "logs",
        "results",
        "records",
        "items",
        "quarantine",
        "quarantine_records",
        "data"
    ];


    for (const key of possibleKeys) {

        if (Array.isArray(data[key]))
            return data[key];

    }


    return [];
}


function value(
    object,
    keys,
    fallback = "—"
) {

    for (const key of keys) {

        if (
            object &&
            object[key] !== undefined &&
            object[key] !== null
        ) {

            return object[key];

        }

    }


    return fallback;
}


function getRisk(log) {

    const raw =
        value(
            log,
            [
                "risk_score",
                "score",
                "risk",
                "riskScore"
            ],
            0
        );


    const parsed =
        Number(raw);


    return Number.isFinite(parsed)
        ? parsed
        : 0;
}


function displayRecipient(log) {
    const recipient = String(
        value(log, ["recipient", "to"], "—")
    );

    if (recipient.toLowerCase().endsWith("@swifpass.local")) {
        return "Security Administrator";
    }

    return recipient;
}


function getVerdict(log) {

    return String(
        value(
            log,
            [
                "verdict",
                "status",
                "classification"
            ],
            "unknown"
        )
    ).toLowerCase();
}


/* -------------------------
   LOAD DATA
-------------------------- */

async function loadEmailLogs() {

    const response =
        await authenticatedFetch(
            API.logs
        );


    if (!response.ok) {

        throw new Error(
            "Could not load email logs"
        );

    }


    const data =
        await response.json();


    emailLogs =
        normalizeArray(data);


    renderLogs();
}


async function loadQuarantine() {

    const response =
        await authenticatedFetch(
            API.quarantine
        );


    if (!response.ok) {

        throw new Error(
            "Could not load quarantine"
        );

    }


    const data =
        await response.json();


    quarantineRecords =
        normalizeArray(data);


    renderQuarantine();
}


async function loadDashboardData() {

    try {

        await Promise.all([
            loadEmailLogs(),
            loadQuarantine()
        ]);


        updateStatistics();

    }

    catch (error) {

        console.error(
            "Dashboard load error:",
            error
        );

    }
}


/* -------------------------
   STATS
-------------------------- */

function updateStatistics() {

    const total =
        emailLogs.length;


    const threats =
        emailLogs.filter(
            (log) => {

                const verdict =
                    getVerdict(log);

                const risk =
                    getRisk(log);


                return (
                    risk >= 70 ||
                    verdict.includes("high") ||
                    verdict.includes("infected") ||
                    verdict.includes("malicious") ||
                    verdict.includes("suspicious")
                );

            }
        ).length;


    const averageRisk =
        total
            ? Math.round(
                emailLogs.reduce(
                    (sum, log) =>
                        sum +
                        getRisk(log),
                    0
                ) / total
            )
            : 0;


    document
        .getElementById(
            "totalEmails"
        )
        .textContent =
        total;


    document
        .getElementById(
            "threatCount"
        )
        .textContent =
        threats;


    document
        .getElementById(
            "quarantineCount"
        )
        .textContent =
        quarantineRecords.length;


    document
        .getElementById(
            "averageRisk"
        )
        .textContent =
        `${averageRisk}%`;
}


/* -------------------------
   RENDER EMAIL LOGS
-------------------------- */

function riskClass(score) {

    if (score >= 70)
        return "risk-high";


    if (score >= 35)
        return "risk-medium";


    return "risk-low";
}


function verdictBadge(verdict) {

    const cleaned =
        String(verdict || "unknown")
            .replaceAll("_", " ")
            .toUpperCase();


    let cssClass = "clean";


    const lower =
        cleaned.toLowerCase();


    if (
        lower.includes("high") ||
        lower.includes("infected") ||
        lower.includes("malicious")
    ) {

        cssClass = "high";

    }

    else if (
        lower.includes("suspicious") ||
        lower.includes("medium")
    ) {

        cssClass = "suspicious";

    }


    return `
        <span class="badge ${cssClass}">
            ${escapeHtml(cleaned)}
        </span>
    `;
}


function renderLogs() {

    const recentBody =
        document.getElementById(
            "recentLogsBody"
        );


    const allBody =
        document.getElementById(
            "allLogsBody"
        );


    recentBody.innerHTML = "";
    allBody.innerHTML = "";


    const sorted =
        [...emailLogs]
            .sort(
                (a, b) => {

                    const dateA =
                        new Date(
                            value(
                                a,
                                [
                                    "created_at",
                                    "timestamp",
                                    "date"
                                ],
                                0
                            )
                        );


                    const dateB =
                        new Date(
                            value(
                                b,
                                [
                                    "created_at",
                                    "timestamp",
                                    "date"
                                ],
                                0
                            )
                        );


                    return dateB - dateA;

                }
            );


    if (!sorted.length) {

        recentBody.innerHTML = `
            <tr>
                <td colspan="6">
                    No email scans available yet.
                </td>
            </tr>
        `;


        allBody.innerHTML = `
            <tr>
                <td colspan="7">
                    No email logs found.
                </td>
            </tr>
        `;


        return;
    }


    sorted
        .slice(0, 8)
        .forEach(
            (log) => {

                const risk =
                    getRisk(log);


                const verdict =
                    getVerdict(log);


                recentBody.insertAdjacentHTML(
                    "beforeend",
                    `
                    <tr>
                        <td>
                            ${escapeHtml(
                                value(
                                    log,
                                    ["sender","from"]
                                )
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                displayRecipient(log)
                            )}
                        </td>

                        <td>
                            ${escapeHtml(
                                value(
                                    log,
                                    ["subject"]
                                )
                            )}
                        </td>

                        <td class="${riskClass(risk)}">
                            ${risk}
                        </td>

                        <td>
                            ${verdictBadge(verdict)}
                        </td>

                        <td>
                            ${formatDate(
                                value(
                                    log,
                                    [
                                        "created_at",
                                        "timestamp",
                                        "date"
                                    ]
                                )
                            )}
                        </td>
                    </tr>
                    `
                );

            }
        );


    sorted.forEach(
        (log) => {

            const risk =
                getRisk(log);


            const verdict =
                getVerdict(log);


            allBody.insertAdjacentHTML(
                "beforeend",
                `
                <tr>

                    <td>
                        ${escapeHtml(
                            value(
                                log,
                                ["id"],
                                ""
                            )
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            value(
                                log,
                                ["sender","from"]
                            )
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            displayRecipient(log)
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            value(
                                log,
                                ["subject"]
                            )
                        )}
                    </td>

                    <td class="${riskClass(risk)}">
                        ${risk}
                    </td>

                    <td>
                        ${verdictBadge(verdict)}
                    </td>

                    <td>
                        ${formatDate(
                            value(
                                log,
                                [
                                    "created_at",
                                    "timestamp",
                                    "date"
                                ]
                            )
                        )}
                    </td>

                </tr>
                `
            );

        }
    );

}


/* -------------------------
   QUARANTINE
-------------------------- */

function renderQuarantine() {

    const body =
        document.getElementById(
            "quarantineBody"
        );


    body.innerHTML = "";


    if (!quarantineRecords.length) {

        body.innerHTML = `
            <tr>
                <td colspan="7">
                    Quarantine is empty.
                </td>
            </tr>
        `;

        return;

    }


    quarantineRecords.forEach(
        (record) => {

            const id =
                value(
                    record,
                    [
                        "id",
                        "record_id"
                    ],
                    ""
                );


            const risk =
                Number(
                    value(
                        record,
                        [
                            "risk_score",
                            "score"
                        ],
                        0
                    )
                );


            body.insertAdjacentHTML(
                "beforeend",
                `
                <tr>

                    <td>
                        ${escapeHtml(id)}
                    </td>

                    <td>
                        ${escapeHtml(
                            value(
                                record,
                                ["sender","from"]
                            )
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            value(
                                record,
                                ["subject"]
                            )
                        )}
                    </td>

                    <td class="${riskClass(risk)}">
                        ${risk}
                    </td>

                    <td>
                        ${escapeHtml(
                            value(
                                record,
                                ["reason"],
                                "Security policy"
                            )
                        )}
                    </td>

                    <td>
                        ${formatDate(
                            value(
                                record,
                                [
                                    "created_at",
                                    "timestamp"
                                ]
                            )
                        )}
                    </td>

                    <td>

                        <button
                            class="delete-button"
                            onclick="deleteQuarantine('${id}')"
                        >
                            Delete
                        </button>

                    </td>

                </tr>
                `
            );

        }
    );

}


async function deleteQuarantine(id) {

    if (!id)
        return;


    if (
        !confirm(
            "Delete this quarantined email?"
        )
    ) {

        return;

    }


    const response =
        await authenticatedFetch(
            `${API.quarantine}/${id}`,
            {
                method: "DELETE"
            }
        );


    if (!response.ok) {

        alert(
            "Unable to delete quarantine record."
        );

        return;

    }


    await loadDashboardData();
}


/* -------------------------
   EMAIL SCANNER
-------------------------- */

const fileInput =
    document.getElementById(
        "emailFile"
    );


fileInput.addEventListener(
    "change",
    () => {

        const file =
            fileInput.files[0];


        document
            .getElementById(
                "selectedFile"
            )
            .textContent =
            file
                ? file.name
                : "No file selected";

    }
);


document
    .getElementById("scanButton")
    .addEventListener(
        "click",
        async () => {

            const file =
                fileInput.files[0];


            if (!file) {

                alert(
                    "Select a .eml file first."
                );

                return;
            }


            const button =
                document.getElementById(
                    "scanButton"
                );


            button.disabled = true;
            button.textContent =
                "Analyzing...";


            try {

                const form =
                    new FormData();


                form.append(
                    "file",
                    file
                );


                const response =
                    await authenticatedFetch(
                        API.scan,
                        {
                            method: "POST",
                            body: form
                        }
                    );


                if (!response.ok) {

                    const text =
                        await response.text();

                    throw new Error(
                        text ||
                        "Email scan failed"
                    );

                }


                const result =
                    await response.json();


                displayScanResult(
                    result
                );


                await loadDashboardData();

            }

            catch (error) {

                console.error(error);

                alert(
                    "Scan failed. Check the API logs."
                );

            }

            finally {

                button.disabled = false;

                button.textContent =
                    "Analyze Email";

            }

        }
    );


function displayScanResult(result) {

    document
        .getElementById(
            "emptyScanState"
        )
        .classList
        .add("hidden");


    document
        .getElementById(
            "scanResults"
        )
        .classList
        .remove("hidden");


    const risk =
        Number(
            value(
                result,
                [
                    "risk_score",
                    "score"
                ],
                0
            )
        );


    const verdict =
        value(
            result,
            ["verdict"],
            "unknown"
        );


    document
        .getElementById(
            "scanVerdict"
        )
        .innerHTML =
        verdictBadge(
            verdict
        );


    document
        .getElementById(
            "scanRisk"
        )
        .textContent =
        `${risk}/100`;


    document
        .getElementById(
            "scanSender"
        )
        .textContent =
        value(
            result,
            [
                "sender",
                "from"
            ],
            "—"
        );


    document
        .getElementById(
            "scanSubject"
        )
        .textContent =
        value(
            result,
            ["subject"],
            "—"
        );


    document
        .getElementById(
            "scanQuarantined"
        )
        .textContent =
        result.quarantined
            ? "YES"
            : "NO";


    const auth =
        result.authentication || {};


    const spf =
        auth.spf?.status || "UNKNOWN";


    const dkim =
        auth.dkim?.status || "UNKNOWN";


    const dmarc =
        auth.dmarc?.status || "UNKNOWN";


    localStorage.setItem(
        "email_security_latest_auth",
        JSON.stringify({
            spf: spf,
            dkim: dkim,
            dmarc: dmarc,
            scanned_at: new Date().toISOString()
        })
    );


    setAuthenticationStatus(
        "spfStatus",
        spf
    );


    setAuthenticationStatus(
        "dkimStatus",
        dkim
    );


    setAuthenticationStatus(
        "dmarcStatus",
        dmarc
    );


    document
        .getElementById(
            "resultSpf"
        )
        .textContent =
        spf;


    document
        .getElementById(
            "resultDkim"
        )
        .textContent =
        dkim;


    document
        .getElementById(
            "resultDmarc"
        )
        .textContent =
        dmarc;


    document
        .getElementById(
            "authScanMessage"
        )
        .textContent =
        "Latest scanned email";


    const findings =
        value(
            result,
            [
                "findings",
                "indicators",
                "reasons"
            ],
            []
        );


    const findingsArea =
        document.getElementById(
            "scanFindings"
        );


    findingsArea.innerHTML = "";


    if (
        Array.isArray(findings) &&
        findings.length
    ) {

        findings.forEach(
            (finding) => {

                const message =
                    typeof finding === "string"
                        ? finding
                        : JSON.stringify(
                            finding
                        );


                findingsArea.insertAdjacentHTML(
                    "beforeend",
                    `
                    <div class="finding">
                        ${escapeHtml(message)}
                    </div>
                    `
                );

            }
        );

    }

    else {

        findingsArea.innerHTML = `
            <div class="finding">
                No additional indicators returned.
            </div>
        `;

    }

}


/* -------------------------
   AUTH STATUS
-------------------------- */

function setAuthenticationStatus(
    elementId,
    status
) {

    const element =
        document.getElementById(
            elementId
        );


    const normalized =
        String(status)
            .toUpperCase();


    element.textContent =
        normalized;


    element.className =
        "auth-status";


    if (normalized === "PASS") {

        element.classList.add(
            "pass"
        );

    }

    else if (
        normalized === "SOFTFAIL" ||
        normalized === "NEUTRAL" ||
        normalized === "NONE"
    ) {

        element.classList.add(
            "warning"
        );

    }

    else if (
        normalized === "FAIL"
    ) {

        element.classList.add(
            "fail"
        );

    }

    else {

        element.classList.add(
            "unknown"
        );

    }

}


/* -------------------------
   NAVIGATION
-------------------------- */

document
    .querySelectorAll(".nav-item")
    .forEach(
        (button) => {

            button.addEventListener(
                "click",
                () => {

                    showSection(
                        button.dataset.section
                    );

                }
            );

        }
    );


function showSection(section) {

    document
        .querySelectorAll(
            ".page-section"
        )
        .forEach(
            element =>
                element.classList.remove(
                    "active-section"
                )
        );


    document
        .querySelectorAll(
            ".nav-item"
        )
        .forEach(
            element =>
                element.classList.remove(
                    "active"
                )
        );


    const target =
        document.getElementById(
            `${section}Section`
        );


    if (target) {

        target.classList.add(
            "active-section"
        );

    }


    const button =
        document.querySelector(
            `[data-section="${section}"]`
        );


    if (button) {

        button.classList.add(
            "active"
        );

    }

}


/* -------------------------
   UTILITIES
-------------------------- */

function escapeHtml(value) {

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function formatDate(value) {

    if (
        !value ||
        value === "—"
    ) {

        return "—";
    }


    const date =
        new Date(value);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return String(value);
    }


    return date.toLocaleString(
        [],
        {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );
}


function restoreLatestAuthentication() {

    const saved =
        localStorage.getItem(
            "email_security_latest_auth"
        );


    if (!saved)
        return;


    try {

        const auth =
            JSON.parse(saved);


        setAuthenticationStatus(
            "spfStatus",
            auth.spf || "UNKNOWN"
        );


        setAuthenticationStatus(
            "dkimStatus",
            auth.dkim || "UNKNOWN"
        );


        setAuthenticationStatus(
            "dmarcStatus",
            auth.dmarc || "UNKNOWN"
        );


        document
            .getElementById(
                "authScanMessage"
            )
            .textContent =
            "Latest scanned email";

    }

    catch (error) {

        console.error(
            "Could not restore latest authentication:",
            error
        );

    }

}


/* -------------------------
   STARTUP
-------------------------- */

window.addEventListener(
    "DOMContentLoaded",
    async () => {

        restoreLatestAuthentication();

        const token =
            getToken();


        const email =
            localStorage.getItem(
                "swifpass_email"
            );


        if (token) {

            document
                .getElementById(
                    "loginOverlay"
                )
                .classList
                .add("hidden");


            if (email) {

                document
                    .getElementById(
                        "tenantName"
                    )
                    .textContent =
                    "Security Administrator";

            }


            await loadDashboardData();

        }

    }
);
