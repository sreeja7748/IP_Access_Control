# middleware.py — just the reusable gate function, nothing else

from fastapi import Request
from fastapi.responses import JSONResponse
from ip_access_control import is_allowed, get_real_ip

async def ip_gate(request: Request, call_next):
    client_ip = get_real_ip(dict(request.headers), request.client.host)

    if not is_allowed(client_ip):
        return JSONResponse(
            status_code=403,
            content={"error": "Access denied", "ip": client_ip}
        )

    return await call_next(request)