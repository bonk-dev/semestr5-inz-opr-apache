export type Log = {
  id: number;
  date: string;
  ip: string;
  method: string;
  path: string;
  status: number;
};

export const logs: Log[] = [
  { id: 1, date: "2026-10-26 14:32:08", ip: "192.168.1.45", method: "GET", path: "/index.php", status: 200 },
  { id: 2, date: "2026-10-26 14:32:05", ip: "203.0.113.77", method: "POST", path: "/wp-login.php", status: 403 },
  { id: 3, date: "2026-10-26 14:31:59", ip: "203.0.113.77", method: "POST", path: "/wp-login.php", status: 403 },
  { id: 4, date: "2026-10-26 14:31:42", ip: "10.0.0.12", method: "GET", path: "/api/users", status: 200 },
  { id: 5, date: "2026-10-26 14:31:10", ip: "198.51.100.9", method: "GET", path: "/admin", status: 404 },
];