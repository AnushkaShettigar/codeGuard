from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from .guard import guard
from .schema import CheckRequest, CheckResponse

app = FastAPI(title="CodeGuard API")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/check", response_model=CheckResponse)
def check_endpoint(request: CheckRequest) -> CheckResponse:
    result = guard(request.code)
    return CheckResponse(**result)


@app.post("/batch", response_model=list[CheckResponse])
def batch_endpoint(requests: list[CheckRequest]) -> list[CheckResponse]:
    return [CheckResponse(**guard(item.code)) for item in requests]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("textcodeguard.api:app", host="0.0.0.0", port=8000, reload=False)