/* express-file-validator.js
   npm init -y
   npm install express multer file-type adm-zip
   node express-file-validator.js
*/

const express = require("express");
const multer = require("multer");
const { fileTypeFromBuffer } = require("file-type");
const AdmZip = require("adm-zip");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// --- Ordner für SAFE Dateien ---
const RECEIVED_FOLDER = path.join(__dirname, "Received");
if (!fs.existsSync(RECEIVED_FOLDER)) fs.mkdirSync(RECEIVED_FOLDER);

// --- Multer Config ---
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
});

// --- Allowed Extensions ---
const ALLOWED_EXTENSIONS = {
    png: ["png"],
    jpg: ["jpg", "jpeg"],
    jpeg: ["jpg", "jpeg"],
    gif: ["gif"],
    pdf: ["pdf"],
    txt: ["txt"],
    md: ["txt", "md"],
    html: ["html", "htm"],
    zip: ["zip"],
    mp4: ["mp4"],
    webm: ["webm"],
    csv: ["csv"],
    docx: ["zip", "docx"],
    dotx: ["zip", "dotx"],
};

// --- Suspicious Patterns ---
const SUSPICIOUS_PATTERNS = [
    /<script\b/i,
    /eval\(/i,
    /base64_decode\(/i,
    /<?php/i,
    /onerror=/i,
    /<iframe/i,
    /system\(/i,
    /\b#!/,
];

// --- Helper Functions ---
function getExt(filename) {
    return (path.extname(filename) || "").replace(".", "").toLowerCase();
}

function hasDoubleExtension(name) {
    const parts = name.split(".");
    return parts.length > 2 && !["tar", "gz", "bak"].includes(parts.at(-2));
}

function hasSuspiciousText(buffer) {
    try {
        const txt = buffer.toString("utf8", 0, Math.min(buffer.length, 4000));
        return SUSPICIOUS_PATTERNS.some((rx) => rx.test(txt));
    } catch {
        return false;
    }
}

function inspectZip(buffer, ext) {
    try {
        const zip = new AdmZip(buffer);
        const entries = zip.getEntries();

        const BLOCKED = ["exe", "bat", "cmd", "sh", "dll", "ps1", "js", "php", "msi"];

        for (const e of entries) {
            const name = e.entryName;

            // Zip Slip check
            if (name.includes("..")) return { safe: false, reason: "Verdächtige Pfade (Zip Slip)" };

            const innerExt = getExt(name);

            // Block dangerous executables
            if (BLOCKED.includes(innerExt)) return { safe: false, reason: `ZIP enthält gefährliche Datei: .${innerExt}` };

            // Block macros in Word files
            if ((ext === "docx" || ext === "dotx") && name.includes("vbaProject.bin")) {
                return { safe: false, reason: "DOCX/DOTX enthält Makros (vbaProject.bin)" };
            }
        }

        return { safe: true };
    } catch {
        return { safe: false, reason: "Konnte ZIP/DOCX nicht lesen." };
    }
}

// --- Frontend ---
app.get("/", (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <body style="font-family:sans-serif; margin:50px;">
      <h2>Datei prüfen</h2>
      <form method="POST" enctype="multipart/form-data" action="/upload">
        <input type="file" name="file" required />
        <button>Upload</button>
      </form>
    </body>
    </html>
    `);
});

// --- Upload Handler ---
app.post("/upload", upload.single("file"), async (req, res) => {
    const reasons = [];

    if (!req.file) return res.json({ ok: false, verdict: "❌ UNSAFE", reasons: ["Keine Datei hochgeladen"] });

    const { originalname, buffer, size } = req.file;
    const ext = getExt(originalname);

    // Filename validation
    if (!/^[a-zA-Z0-9._-]{1,255}$/.test(originalname)) reasons.push("Ungültiger Dateiname.");
    if (hasDoubleExtension(originalname)) reasons.push("Verdächtige doppelte Extension.");

    // Magic-type validation
    const detected = await fileTypeFromBuffer(buffer);
    if (!detected) reasons.push("Dateityp unbekannt oder nicht analysierbar.");
    else if (!ALLOWED_EXTENSIONS[ext] || !ALLOWED_EXTENSIONS[ext].includes(detected.ext)) {
        reasons.push(`Extension passt nicht zum Inhalt (${detected.ext})`);
    }

    // Text scan
    if (["txt", "html", "md"].includes(ext)) {
        if (hasSuspiciousText(buffer)) reasons.push("Verdächtiger Textinhalt entdeckt.");
    }

    // ZIP/DOCX/DOTX check
    if (ext === "zip" || ext === "docx" || ext === "dotx") {
        const zipCheck = inspectZip(buffer, ext);
        if (!zipCheck.safe) reasons.push(zipCheck.reason);
    }

    const safe = reasons.length === 0;

    // --- SAFE Datei speichern ---
    if (safe) {
        const savePath = path.join(RECEIVED_FOLDER, originalname);
        let finalPath = savePath;
        let counter = 1;
        while (fs.existsSync(finalPath)) {
            const name = path.parse(originalname).name;
            const extension = path.parse(originalname).ext;
            finalPath = path.join(RECEIVED_FOLDER, `${name}(${counter})${extension}`);
            counter++;
        }
        fs.writeFileSync(finalPath, buffer);
    }

    res.json({
        ok: safe,
        verdict: safe ? "✔ SAFE" : "❌ UNSAFE",
        filename: originalname,
        size,
        detected: detected || "unknown",
        reasons,
    });
});

// --- Error Handler ---
app.use((err, req, res, next) => {
    if (err.code === "LIMIT_FILE_SIZE") {
        return res.json({ ok: false, verdict: "❌ UNSAFE", reasons: ["Datei zu groß. Max 10MB."] });
    }
    res.json({ ok: false, verdict: "❌ UNSAFE", reasons: [err.message] });
});

// --- Start Server ---
app.listen(PORT, () => console.log(`🚀 Server läuft auf http://localhost:${PORT}`));
