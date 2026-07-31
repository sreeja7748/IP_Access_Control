💻🔐 IP Access Control

🚦 A lightweight IP-based access control system built with FastAPI

Control who can access your FastAPI application by checking the client's IP address before allowing requests to reach your API endpoints.

The project uses Python's built-in ipaddress module to validate IP addresses and FastAPI middleware to create a simple security gate. 🛡️

✨ Features

🔐 IP Allowlist — Only approved IP ranges can access the application.
⚡ Fast IP Checking — IP networks are compiled once at startup.
🌐 IPv4 & IPv6 Parsing — Supports both IPv4 and IPv6 addresses.
🔄 IPv4-Mapped IPv6 Support — Handles addresses such as ::ffff:192.168.1.1.
🚪 Automatic Request Blocking — Unauthorized clients receive HTTP 403.
🔍 Proxy-Aware IP Detection — Supports common proxy/load-balancer headers.
🧪 Pytest Tests — Includes tests for valid, invalid, malformed, and edge-case IP addresses.
🧩 Reusable Middleware — The IP gate can be separated from the main application.
