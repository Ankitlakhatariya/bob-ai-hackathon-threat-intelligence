import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import openai

from app.main import app
from app.services.llm_service import OpenAIThreatAnalysisService

client = TestClient(app)

@pytest.fixture
def mock_openai_response():
    mock_parsed = MagicMock()
    mock_parsed.assessment = "This is a severe threat."
    mock_parsed.confidence = 0.95
    mock_parsed.key_findings = ["Finding 1", "Finding 2"]
    mock_parsed.evidence = ["Evidence 1"]
    mock_parsed.potential_attack_chain = ["Step 1", "Step 2"]
    mock_parsed.mitre_assessment = []
    mock_parsed.uncertainties = ["Unknown actor"]
    mock_parsed.recommended_investigation_focus = ["Check logs"]
    mock_parsed.bluf = "Severe threat detected."
    mock_parsed.priority_explanation = "High priority due to evidence."

    mock_choice = MagicMock()
    mock_choice.message.parsed = mock_parsed

    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    return mock_response

@pytest.mark.asyncio
async def test_llm_service_missing_api_key():
    with patch("app.services.llm_service.settings") as mock_settings:
        mock_settings.OPENAI_API_KEY = None
        service = OpenAIThreatAnalysisService()
        assert service.is_configured() is False

@pytest.mark.asyncio
async def test_ai_analyze_threat_missing_api_key():
    with patch("app.api.ai.llm_service.is_configured", return_value=False):
        response = client.post("/api/v1/ai/analyze-threat/INC-1001")
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "AI_NOT_CONFIGURED"

@pytest.mark.asyncio
async def test_ai_analyze_threat_not_found(db_session):
    with patch("app.api.ai.llm_service.is_configured", return_value=True):
        response = client.post("/api/v1/ai/analyze-threat/INVALID-ID")
        assert response.status_code == 404

@pytest.mark.asyncio
async def test_llm_service_auth_error():
    service = OpenAIThreatAnalysisService()
    service.client = MagicMock()
    service.client.beta.chat.completions.parse = AsyncMock(side_effect=openai.AuthenticationError(
        message="Invalid API Key", 
        response=MagicMock(),
        body={}
    ))
    
    with pytest.raises(openai.AuthenticationError):
        await service.analyze_threat({"threat": "context"})
