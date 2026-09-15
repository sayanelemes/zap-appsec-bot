import logging
import os
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from bot.api.auth import get_current_tma_user
from bot.config.config import settings
from bot.services.scan_manager import scan_manager
from bot.services.zap import ZapService

logger = logging.getLogger(__name__)


class StartScanRequest(BaseModel):
    target: str = Field(..., description="URL веб-сайта для DAST или ссылка на GitHub для SAST", min_length=3)
    mode: Literal["passive", "fast", "full"] = Field(
        default="fast",
        description="Глубина сканирования (passive, fast, full)",
    )


class FindingItem(BaseModel):
    title: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    description: str
    param: str = ""
    cwe: str = ""
    cve: str = ""
    cvss: float = 0.0


class ScanStatusResponse(BaseModel):
    state: Literal["idle", "running", "stopped", "finished"]
    progress: int
    logs: list[str]
    findings: list[FindingItem]
    target: str = ""
    mode: str = ""
    scan_type: str = ""
    ai_analysis: list[str] = []
    ai_loading: bool = False


def create_app() -> FastAPI:
    """Создает и настраивает экземпляр приложения FastAPI для Telegram Mini App."""
    app = FastAPI(
        title="Cyber SOC Vulnerability Scanner API",
        description="API шлюз для управления OWASP ZAP DAST и GitHub SAST через Telegram Mini App",
        version="1.0.0",
    )

    # CORS для корректной работы WebApp iframe
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    async def health_check() -> dict[str, Any]:
        """Проверка состояния API и связи с демоном OWASP ZAP."""
        zap_alive = False
        try:
            api_key = settings.ZAP_API_KEY.get_secret_value() if (settings and settings.ZAP_API_KEY) else ""
            proxy = settings.ZAP_PROXY if settings else "http://127.0.0.1:8090"
            zap = ZapService(proxy_url=proxy, api_key=api_key)
            zap_alive = await zap.check_health()
        except Exception:
            zap_alive = False

        return {
            "status": "ok",
            "zap_daemon_connected": zap_alive,
            "zap_endpoint": settings.zap_endpoint if settings else "http://zap:8080",
            "scanner_busy": scan_manager.is_running,
        }

    @app.post(
        "/api/scan/start",
        response_model=ScanStatusResponse,
        summary="Запуск нового сканирования",
    )
    async def start_scan(
        body: StartScanRequest,
        user: dict[str, Any] = Depends(get_current_tma_user),
    ) -> dict[str, Any]:
        """
        Запуск DAST сканирования сайта или SAST аудита зависимостей GitHub.
        """
        user_id = user.get("id")
        try:
            status_data = await scan_manager.start_scan(
                target=body.target,
                mode=body.mode,
                user_id=user_id,
            )
            return status_data
        except RuntimeError as e:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(e),
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            )
        except Exception as e:
            logger.exception("Ошибка при запуске сканирования из API: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Не удалось запустить сканирование: {e}",
            )

    @app.post(
        "/api/scan/stop",
        response_model=ScanStatusResponse,
        summary="Экстренная остановка активного сканирования",
    )
    async def stop_scan(
        user: dict[str, Any] = Depends(get_current_tma_user),
    ) -> dict[str, Any]:
        """
        Принудительно останавливает активный аудит.
        """
        status_data = await scan_manager.stop_scan()
        return status_data

    @app.get(
        "/api/scan/status",
        response_model=ScanStatusResponse,
        summary="Получение текущего статуса сканирования, прогресса, логов и найденных уязвимостей",
    )
    async def get_scan_status(
        user: dict[str, Any] = Depends(get_current_tma_user),
    ) -> dict[str, Any]:
        """
        Возвращает состояние сканера для динамического обновления UI в Mini App.
        """
        return scan_manager.get_status()

    @app.post(
        "/api/scan/ai-advisor",
        summary="Запуск AI-аудита уязвимостей через Google Gemini",
    )
    async def generate_ai_advisor(
        user: dict[str, Any] = Depends(get_current_tma_user),
    ) -> dict[str, Any]:
        """
        Вызывает Google Gemini API для генерации простого объяснения рисков
        и готовых задач /goal для AI-агентов кодогенерации (Cursor / Antigravity / Claude Code).
        """
        try:
            chunks = await scan_manager.run_ai_audit()
            return {"status": "ok", "analysis": chunks}
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            )
        except Exception as e:
            logger.exception("Ошибка генерации ИИ-аудита в API: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Не удалось сгенерировать ИИ-аудит: {e}",
            )

    # Монтирование статических файлов Mini App UI
    static_dir = os.path.join(os.getcwd(), "static")
    os.makedirs(static_dir, exist_ok=True)
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


app = create_app()
