export async function api(url, options = {}) {
  let response;
  try {
    response = await fetch(url, { credentials: "same-origin", ...options });
  } catch {
    throw new Error("Tidak dapat terhubung ke server. Periksa koneksi lalu coba kembali.");
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("Server mengirimkan respons yang tidak valid.");
  }

  if (!response.ok) throw new Error(data.error || "Permintaan tidak dapat diproses.");
  return data;
}
