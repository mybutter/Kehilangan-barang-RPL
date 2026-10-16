const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "uploads");
const SESSION_DAYS = 7;
const STATUSES = ["Belum Ditemukan", "Sedang Ditelusuri", "Barang Ditemukan", "Sudah Dikembalikan"];
const CATEGORIES = ["Elektronik", "Dokumen", "Aksesori", "Pakaian", "Kendaraan", "Lainnya"];
const MIME_EXTENSIONS = { "image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp" };

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "kehilangan.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    nim TEXT UNIQUE,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    username TEXT UNIQUE,
    study_program TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student', 'staff')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_number TEXT UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    item_name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    photo TEXT,
    location TEXT NOT NULL,
    lost_at TEXT NOT NULL,
    contact TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Belum Ditemukan',
    staff_note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS report_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    staff_id INTEGER REFERENCES users(id),
    status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS reports_user_id_idx ON reports(user_id);
  CREATE INDEX IF NOT EXISTS reports_status_idx ON reports(status);
  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
`);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, callback) => {
    if (!Object.hasOwn(MIME_EXTENSIONS, file.mimetype)) {
      return callback(new Error("Foto harus berformat JPG, PNG, atau WebP."));
    }
    callback(null, true);
  },
});

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
  });
  next();
});
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use("/uploads", express.static(UPLOAD_DIR, { maxAge: "1d", immutable: true }));

const hashToken = (token) => crypto.createHash("sha256").update(token).digest("hex");
const publicUser = (user) => ({
  id: user.id,
  name: user.name,
  nim: user.nim,
  email: user.email,
  username: user.username,
  studyProgram: user.study_program,
  role: user.role,
});
const cleanReport = (report, includePrivate = false) => {
  const result = {
    id: report.id,
    reportNumber: report.report_number,
    itemName: report.item_name,
    category: report.category,
    description: report.description,
    photo: report.photo,
    location: report.location,
    lostAt: report.lost_at,
    status: report.status,
    staffNote: report.staff_note,
    createdAt: report.created_at,
    updatedAt: report.updated_at,
  };
  if (includePrivate) {
    result.contact = report.contact;
    result.reporterName = report.reporter_name;
    result.nim = report.nim;
  }
  return result;
};

function authenticate(req, res, next) {
  const token = req.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("sid="))?.slice(4);
  if (!token) return res.status(401).json({ error: "Silakan masuk untuk melanjutkan." });

  const session = db.prepare(`
    SELECT users.*, sessions.expires_at FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
  `).get(hashToken(token));
  if (!session || session.expires_at <= Date.now()) {
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
    res.clearCookie("sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" });
    return res.status(401).json({ error: "Sesi Anda telah berakhir. Silakan masuk kembali." });
  }
  req.user = session;
  next();
}

const requireStaff = (req, res, next) => req.user.role === "staff"
  ? next()
  : res.status(403).json({ error: "Halaman ini hanya dapat diakses oleh petugas." });

function validateReport(body) {
  const fields = {
    itemName: "Nama barang",
    category: "Kategori",
    description: "Deskripsi",
    location: "Lokasi terakhir",
    lostAt: "Tanggal dan waktu kehilangan",
    contact: "Kontak",
  };
  for (const [field, label] of Object.entries(fields)) {
    if (typeof body[field] !== "string" || !body[field].trim()) return `${label} wajib diisi.`;
    if (body[field].trim().length > 1200) return `${label} terlalu panjang.`;
  }
  if (body.itemName.trim().length > 120) return "Nama barang maksimal 120 karakter.";
  if (body.location.trim().length > 180) return "Lokasi maksimal 180 karakter.";
  if (body.contact.trim().length > 40) return "Kontak maksimal 40 karakter.";
  if (!CATEGORIES.includes(body.category)) return "Kategori barang tidak valid.";
  if (Number.isNaN(Date.parse(body.lostAt))) return "Tanggal kehilangan tidak valid.";
  return null;
}

app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

app.get("/api/auth/session", (req, res) => {
  const token = req.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("sid="))?.slice(4);
  if (!token) return res.json({ user: null });
  const session = db.prepare(`
    SELECT users.*, sessions.expires_at FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
  `).get(hashToken(token));
  if (!session || session.expires_at <= Date.now()) {
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
    res.clearCookie("sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" });
    return res.json({ user: null });
  }
  res.json({ user: publicUser(session) });
});

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const { name, nim, email, studyProgram, password } = req.body;
    if (![name, nim, email, studyProgram, password].every((value) => typeof value === "string" && value.trim())) {
      return res.status(400).json({ error: "Lengkapi semua data yang diminta." });
    }
    if (name.trim().length > 120 || nim.trim().length > 30 || studyProgram.trim().length > 120) {
      return res.status(400).json({ error: "Beberapa data melebihi batas panjang." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return res.status(400).json({ error: "Format email tidak valid." });
    if (password.length < 8 || Buffer.byteLength(password, "utf8") > 72) return res.status(400).json({ error: "Kata sandi harus berisi 8–72 byte." });
    if (!/^[A-Za-z0-9.-]+$/.test(nim.trim())) return res.status(400).json({ error: "NIM hanya boleh berisi huruf, angka, titik, atau tanda hubung." });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = db.prepare(`
      INSERT INTO users (name, nim, email, study_program, password_hash)
      VALUES (?, ?, ?, ?, ?)
      RETURNING id, name, nim, email, username, study_program, role
    `).get(name.trim(), nim.trim(), email.trim(), studyProgram.trim(), passwordHash);
    res.status(201).json({ user: publicUser(user) });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") return res.status(409).json({ error: "NIM atau email tersebut sudah terdaftar." });
    next(error);
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { identifier, password } = req.body;
    if (typeof identifier !== "string" || typeof password !== "string" || !identifier.trim() || !password) {
      return res.status(400).json({ error: "Email, NIM, atau username dan kata sandi wajib diisi." });
    }
    const user = db.prepare(`
      SELECT * FROM users WHERE email = ? COLLATE NOCASE OR nim = ? OR username = ?
    `).get(identifier.trim(), identifier.trim(), identifier.trim());
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Data masuk tidak sesuai." });
    }
    const token = crypto.randomBytes(32).toString("base64url");
    const expiresAt = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
    db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)").run(hashToken(token), user.id, expiresAt);
    db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(Date.now());
    res.cookie("sid", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
      path: "/",
    });
    res.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/logout", (req, res) => {
  const token = req.get("cookie")?.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("sid="))?.slice(4);
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
  res.clearCookie("sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" });
  res.json({ success: true });
});

app.get("/api/auth/me", authenticate, (req, res) => res.json({ user: publicUser(req.user) }));

app.patch("/api/profile", authenticate, (req, res, next) => {
  try {
    const { name, email, studyProgram } = req.body;
    if (![name, email, studyProgram].every((value) => typeof value === "string" && value.trim())) {
      return res.status(400).json({ error: "Nama, email, dan program studi wajib diisi." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return res.status(400).json({ error: "Format email tidak valid." });
    const user = db.prepare(`
      UPDATE users SET name = ?, email = ?, study_program = ?
      WHERE id = ? RETURNING id, name, nim, email, username, study_program, role
    `).get(name.trim(), email.trim(), studyProgram.trim(), req.user.id);
    res.json({ user: publicUser(user) });
  } catch (error) {
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") return res.status(409).json({ error: "Email tersebut sudah digunakan." });
    next(error);
  }
});

app.get("/api/dashboard", authenticate, (req, res) => {
  if (req.user.role === "staff") {
    const stats = db.prepare(`
      SELECT COUNT(*) AS total,
        SUM(status = 'Belum Ditemukan') AS new,
        SUM(status = 'Sedang Ditelusuri') AS searching,
        SUM(status = 'Barang Ditemukan') AS found,
        SUM(status = 'Sudah Dikembalikan') AS returned
      FROM reports
    `).get();
    return res.json({ stats, reports: db.prepare(`
      SELECT reports.*, users.name AS reporter_name, users.nim FROM reports
      JOIN users ON users.id = reports.user_id ORDER BY reports.created_at DESC LIMIT 8
    `).all().map((report) => cleanReport(report, true)) });
  }
  const stats = db.prepare(`
    SELECT COUNT(*) AS total,
      SUM(status = 'Sedang Ditelusuri') AS inProgress,
      SUM(status = 'Barang Ditemukan') AS found,
      SUM(status = 'Sudah Dikembalikan') AS returned
    FROM reports WHERE user_id = ?
  `).get(req.user.id);
  const reports = db.prepare("SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC LIMIT 6")
    .all(req.user.id).map((report) => cleanReport(report));
  res.json({ stats, reports });
});

app.get("/api/reports/mine", authenticate, (req, res) => {
  const reports = db.prepare("SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC")
    .all(req.user.id).map((report) => cleanReport(report));
  res.json({ reports });
});

app.post("/api/reports", authenticate, (req, res, next) => {
  if (req.user.role !== "student") return res.status(403).json({ error: "Akun petugas tidak dapat membuat laporan mahasiswa." });
  upload.single("photo")(req, res, (uploadError) => {
    if (uploadError) return res.status(400).json({ error: uploadError.message });
    try {
      const error = validateReport(req.body);
      if (error) return res.status(400).json({ error });
      let photo = null;
      if (req.file) {
        const bytes = req.file.buffer;
        const mime = req.file.mimetype;
        const validSignature = mime === "image/jpeg" ? bytes[0] === 0xff && bytes[1] === 0xd8
          : mime === "image/png" ? bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
            : bytes.toString("ascii", 0, 4) === "RIFF" && bytes.toString("ascii", 8, 12) === "WEBP";
        if (!validSignature) return res.status(400).json({ error: "Isi foto tidak sesuai dengan format gambar yang dipilih." });
        const filename = `${crypto.randomUUID()}${MIME_EXTENSIONS[mime]}`;
        fs.writeFileSync(path.join(UPLOAD_DIR, filename), bytes, { flag: "wx" });
        photo = `/uploads/${filename}`;
      }
      const createReport = db.transaction(() => {
        const result = db.prepare(`
          INSERT INTO reports (user_id, item_name, category, description, photo, location, lost_at, contact)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(req.user.id, req.body.itemName.trim(), req.body.category, req.body.description.trim(),
          photo, req.body.location.trim(), new Date(req.body.lostAt).toISOString(), req.body.contact.trim());
        const reportNumber = `LKB-${new Date().getFullYear()}-${String(result.lastInsertRowid).padStart(4, "0")}`;
        db.prepare("UPDATE reports SET report_number = ? WHERE id = ?").run(reportNumber, result.lastInsertRowid);
        db.prepare("INSERT INTO report_updates (report_id, status, note) VALUES (?, ?, ?)").run(result.lastInsertRowid, STATUSES[0], "Laporan berhasil dikirim.");
        return db.prepare("SELECT * FROM reports WHERE id = ?").get(result.lastInsertRowid);
      });
      res.status(201).json({ report: cleanReport(createReport()), message: "Laporan berhasil dikirim." });
    } catch (error) {
      next(error);
    }
  });
});

app.get("/api/reports/search", (req, res) => {
  const query = typeof req.query.q === "string" ? req.query.q.trim() : "";
  if (query.length < 3 || query.length > 100) return res.status(400).json({ error: "Masukkan minimal 3 karakter untuk mencari laporan." });
  const reports = db.prepare(`
    SELECT * FROM reports
    WHERE report_number = ? COLLATE NOCASE
      OR item_name LIKE ? ESCAPE '\\'
      OR category LIKE ? ESCAPE '\\'
    ORDER BY created_at DESC LIMIT 20
  `).all(query, `%${query.replace(/[\\%_]/g, "\\$&")}%`, `%${query.replace(/[\\%_]/g, "\\$&")}%`)
    .map((report) => cleanReport(report));
  res.json({ reports });
});

app.get("/api/reports/:reportNumber", (req, res) => {
  const report = db.prepare("SELECT * FROM reports WHERE report_number = ? COLLATE NOCASE").get(req.params.reportNumber);
  if (!report) return res.status(404).json({ error: "Laporan tidak ditemukan." });
  const updates = db.prepare("SELECT status, note, created_at AS createdAt FROM report_updates WHERE report_id = ? ORDER BY id ASC")
    .all(report.id);
  res.json({ report: cleanReport(report), updates });
});

app.get("/api/found", (_req, res) => {
  const reports = db.prepare(`
    SELECT * FROM reports WHERE status = 'Barang Ditemukan' ORDER BY updated_at DESC LIMIT 30
  `).all().map((report) => cleanReport(report));
  res.json({ reports });
});

app.get("/api/staff/reports", authenticate, requireStaff, (req, res) => {
  const status = typeof req.query.status === "string" ? req.query.status : "";
  const query = typeof req.query.q === "string" ? req.query.q.trim() : "";
  const reports = db.prepare(`
    SELECT reports.*, users.name AS reporter_name, users.nim FROM reports
    JOIN users ON users.id = reports.user_id
    WHERE (? = '' OR reports.status = ?)
      AND (? = '' OR reports.report_number LIKE ? OR reports.item_name LIKE ? OR users.name LIKE ? OR users.nim LIKE ?)
    ORDER BY CASE reports.status WHEN 'Belum Ditemukan' THEN 1 WHEN 'Sedang Ditelusuri' THEN 2 WHEN 'Barang Ditemukan' THEN 3 ELSE 4 END,
      reports.created_at DESC
    LIMIT 100
  `).all(status, status, query, `%${query}%`, `%${query}%`, `%${query}%`, `%${query}%`)
    .map((report) => cleanReport(report, true));
  res.json({ reports });
});

app.post("/api/staff/reports", authenticate, requireStaff, (req, res) => {
  const error = validateReport(req.body);
  if (error) return res.status(400).json({ error });
  const { status, note } = req.body;
  if (!STATUSES.includes(status)) return res.status(400).json({ error: "Status laporan tidak valid." });
  if (typeof note !== "string" || note.length > 500) return res.status(400).json({ error: "Catatan maksimal 500 karakter." });
  const createReport = db.transaction(() => {
    const result = db.prepare(`
      INSERT INTO reports (user_id, item_name, category, description, location, lost_at, contact, status, staff_note)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.user.id, req.body.itemName.trim(), req.body.category, req.body.description.trim(),
      req.body.location.trim(), new Date(req.body.lostAt).toISOString(), req.body.contact.trim(), status, note.trim());
    const reportNumber = `LKB-${new Date().getFullYear()}-${String(result.lastInsertRowid).padStart(4, "0")}`;
    db.prepare("UPDATE reports SET report_number = ? WHERE id = ?").run(reportNumber, result.lastInsertRowid);
    db.prepare("INSERT INTO report_updates (report_id, staff_id, status, note) VALUES (?, ?, ?, ?)")
      .run(result.lastInsertRowid, req.user.id, status, note.trim() || "Laporan dicatat oleh petugas.");
    return db.prepare(`
      SELECT reports.*, users.name AS reporter_name, users.nim FROM reports
      JOIN users ON users.id = reports.user_id WHERE reports.id = ?
    `).get(result.lastInsertRowid);
  });
  res.status(201).json({ report: cleanReport(createReport(), true), message: "Laporan berhasil ditambahkan." });
});

app.patch("/api/staff/reports/:id", authenticate, requireStaff, (req, res) => {
  const error = validateReport(req.body);
  if (error) return res.status(400).json({ error });
  const { status, note } = req.body;
  if (!STATUSES.includes(status)) return res.status(400).json({ error: "Status laporan tidak valid." });
  if (typeof note !== "string" || note.length > 500) return res.status(400).json({ error: "Catatan maksimal 500 karakter." });
  const report = db.prepare("SELECT * FROM reports WHERE id = ?").get(req.params.id);
  if (!report) return res.status(404).json({ error: "Laporan tidak ditemukan." });
  const update = db.transaction(() => {
    db.prepare(`
      UPDATE reports SET item_name = ?, category = ?, description = ?, location = ?, lost_at = ?,
        contact = ?, status = ?, staff_note = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    `).run(req.body.itemName.trim(), req.body.category, req.body.description.trim(), req.body.location.trim(),
      new Date(req.body.lostAt).toISOString(), req.body.contact.trim(), status, note.trim(), report.id);
    db.prepare("INSERT INTO report_updates (report_id, staff_id, status, note) VALUES (?, ?, ?, ?)")
      .run(report.id, req.user.id, status, note.trim());
    return db.prepare(`
      SELECT reports.*, users.name AS reporter_name, users.nim FROM reports
      JOIN users ON users.id = reports.user_id WHERE reports.id = ?
    `).get(report.id);
  });
  res.json({ report: cleanReport(update(), true), message: "Laporan berhasil diperbarui." });
});

app.delete("/api/staff/reports/:id", authenticate, requireStaff, (req, res) => {
  const report = db.prepare("SELECT id, photo FROM reports WHERE id = ?").get(req.params.id);
  if (!report) return res.status(404).json({ error: "Laporan tidak ditemukan." });
  db.prepare("DELETE FROM reports WHERE id = ?").run(report.id);
  if (report.photo) {
    const filename = path.basename(report.photo);
    const photoPath = path.join(UPLOAD_DIR, filename);
    if (photoPath.startsWith(`${UPLOAD_DIR}${path.sep}`) && fs.existsSync(photoPath)) {
      fs.unlinkSync(photoPath);
    }
  }
  res.json({ success: true, message: "Laporan berhasil dihapus." });
});

app.use("/api", (_req, res) => res.status(404).json({ error: "Endpoint API tidak ditemukan." }));
app.use(express.static(path.join(ROOT, "public"), { extensions: ["html"] }));
app.get("*splat", (_req, res) => res.sendFile(path.join(ROOT, "public", "index.html")));

app.use((error, _req, res, _next) => {
  console.error(error);
  if (res.headersSent) return;
  res.status(500).json({ error: "Terjadi kesalahan pada server. Silakan coba kembali." });
});

app.listen(PORT, () => console.log(`Sistem Kehilangan Barang berjalan di http://localhost:${PORT}`));
