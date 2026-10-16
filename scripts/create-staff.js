const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");
const path = require("node:path");
const fs = require("node:fs");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

async function main() {
  const databasePath = path.join(__dirname, "..", "data", "kehilangan.sqlite");
  if (!fs.existsSync(databasePath)) {
    console.error("Database belum tersedia. Jalankan aplikasi terlebih dahulu dengan: npm start");
    process.exitCode = 1;
    return;
  }
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const name = (await rl.question("Nama petugas: ")).trim();
    const email = (await rl.question("Email petugas: ")).trim();
    const username = (await rl.question("Username petugas: ")).trim();
    const password = await rl.question("Kata sandi (minimal 8 karakter): ");
    if (!name || !email || !username || password.length < 8) {
      throw new Error("Nama, email, username wajib diisi dan kata sandi minimal 8 karakter.");
    }
    const db = new Database(databasePath);
    const passwordHash = await bcrypt.hash(password, 12);
    db.prepare(`
      INSERT INTO users (name, email, username, study_program, password_hash, role)
      VALUES (?, ?, ?, 'Petugas Keamanan', ?, 'staff')
    `).run(name, email, username, passwordHash);
    db.close();
    console.log(`Akun petugas ${username} berhasil dibuat.`);
  } finally {
    rl.close();
  }
}

main().catch((error) => {
  if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
    console.error("Email atau username tersebut sudah digunakan.");
  } else {
    console.error(error.message);
  }
  process.exitCode = 1;
});
