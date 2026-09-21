from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .config import get_settings
from .indicators import IndicatorValidationError
from .models import AnalysisResult, AnalyzeRequest, BatchAnalyzeRequest, ProviderState
from .service import ThreatIntelService

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    service = ThreatIntelService(settings)
    app.state.service = service
    try:
        yield
    finally:
        await service.close()


app = FastAPI(
    title="praticaAPIsystem",
    version=settings.app_version,
    description="Defensive IOC enrichment API for blue team investigations.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)


@app.exception_handler(IndicatorValidationError)
async def indicator_validation_handler(_: Request, exc: IndicatorValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name, "version": settings.app_version}


@app.get("/v1/providers", response_model=list[ProviderState])
async def providers(request: Request) -> list[ProviderState]:
    service: ThreatIntelService = request.app.state.service
    return service.provider_states()


@app.post("/v1/analyze", response_model=AnalysisResult)
async def analyze(payload: AnalyzeRequest, request: Request) -> AnalysisResult:
    service: ThreatIntelService = request.app.state.service
    return await service.analyze(payload.indicator)


@app.post("/v1/analyze/batch", response_model=list[AnalysisResult])
async def analyze_batch(
    payload: BatchAnalyzeRequest,
    request: Request,
) -> list[AnalysisResult]:
    service: ThreatIntelService = request.app.state.service
    try:
        return await service.analyze_batch(payload.indicators)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
