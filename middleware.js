const COOKIE_NAME = 'site_auth';
const LOGIN_PATH = '/__login';

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get('cookie') || '';
  const match = cookieHeader
    .split(';')
    .map((c) => c.trim())
    .find((c) => c.startsWith(name + '='));
  return match ? match.split('=')[1] : null;
}

function loginPage(errorMessage) {
  return `<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>เข้าสู่ระบบ</title>
<style>
  body { font-family: 'Tahoma', sans-serif; background: #f3f4f6; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .box { background: white; padding: 32px; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.15); width: 100%; max-width: 320px; }
  h1 { font-size: 18px; color: #374151; margin: 0 0 20px 0; text-align: center; }
  input { box-sizing: border-box; width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 14px; margin-bottom: 12px; }
  button { width: 100%; padding: 10px; background: #2563eb; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 14px; }
  button:hover { background: #1d4ed8; }
  .error { color: #dc2626; font-size: 13px; margin-bottom: 12px; text-align: center; }
</style>
</head>
<body>
  <form class="box" method="POST" action="${LOGIN_PATH}">
    <h1>กรุณาใส่รหัสผ่านเพื่อเข้าใช้งาน</h1>
    ${errorMessage ? `<div class="error">${errorMessage}</div>` : ''}
    <input type="password" name="password" placeholder="รหัสผ่าน" autofocus required>
    <button type="submit">เข้าสู่ระบบ</button>
  </form>
</body>
</html>`;
}

export default async function middleware(request) {
  const expectedPass = process.env.SITE_PASSWORD;

  if (!expectedPass) {
    return new Response('Site password is not configured (missing SITE_PASSWORD env var).', {
      status: 500,
    });
  }

  const expectedHash = await sha256Hex(expectedPass);
  const url = new URL(request.url);

  // จัดการการ submit ฟอร์ม login
  if (url.pathname === LOGIN_PATH && request.method === 'POST') {
    const formData = await request.formData();
    const submittedPass = formData.get('password') || '';

    if (submittedPass === expectedPass) {
      return new Response(null, {
        status: 303,
        headers: {
          Location: '/',
          'Set-Cookie': `${COOKIE_NAME}=${expectedHash}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`,
        },
      });
    }

    return new Response(loginPage('รหัสผ่านไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง'), {
      status: 401,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  }

  // เช็ค cookie ว่าล็อกอินอยู่แล้วหรือยัง
  const cookieValue = getCookie(request, COOKIE_NAME);
  if (cookieValue === expectedHash) {
    return; // ผ่าน -> เข้าเว็บได้ตามปกติ
  }

  // ยังไม่ล็อกอิน -> แสดงหน้า login
  return new Response(loginPage(null), {
    status: 401,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
}
