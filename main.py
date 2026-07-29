from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from ip_access_control import is_allowed, get_real_ip

app = FastAPI()

@app.middleware("http")
async def ip_check(request: Request, call_next):
    client_ip = get_real_ip(dict(request.headers), request.client.host)

    if not is_allowed(client_ip):
        return JSONResponse(
            status_code=403,
            content={"error": "Access denied", "ip": client_ip}
        )

    return await call_next(request)

@app.get("/")
async def home():
    return {"message": "You are allowed in!"}