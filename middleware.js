export const config = {
  matcher: '/:path*',
};

export default function middleware(request) {
  const authHeader = request.headers.get('authorization');

  const expectedUser = process.env.SITE_USER || 'admin';
  const expectedPass = process.env.SITE_PASSWORD; // ตั้งค่านี้ใน Vercel Dashboard

  if (!expectedPass) {
    // ยังไม่ได้ตั้งรหัสผ่านใน Environment Variables
    return new Response('Site password is not configured (missing SITE_PASSWORD env var).', {
      status: 500,
    });
  }

  if (authHeader) {
    const base64Credentials = authHeader.split(' ')[1] || '';
    const credentials = atob(base64Credentials);
    const [user, pass] = credentials.split(':');

    if (user === expectedUser && pass === expectedPass) {
      return; // ผ่าน -> ให้เข้าเว็บได้ตามปกติ
    }
  }

  return new Response('Authentication required.', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Secure Area"',
    },
  });
}
