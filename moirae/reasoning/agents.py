"""Agents components extracted from the original Moirae runner."""
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from ..evidence.tools import AndroidEvidenceDeps, first_related_event, inspect_screen, list_events, list_screens, list_ui_events, next_screen, read_api_calls, read_raw_event, read_raw_ui_event, read_related_events, read_ui_state
from ..config import API_KEY, BASE_URL, VISION_MODEL_NAME, TEXT_MODEL_NAME, JUDGE_MODEL_NAME, STRUCTURED_OUTPUT_RETRIES
from .prompts import API_AGENT_PROMPT, JUDGE_AGENT_PROMPT, UI_EVENT_AGENT_PROMPT, VISION_AGENT_PROMPT
from .schemas import APIAgentResult, AndroidMalwareAnalysisOutput, UIEventAgentResult, VisionAgentResult


provider = OpenAIProvider(base_url=BASE_URL, api_key=API_KEY or "not-configured")
vision_model = OpenAIChatModel(VISION_MODEL_NAME, provider=provider)
text_model = OpenAIChatModel(TEXT_MODEL_NAME, provider=provider)
judge_model = OpenAIChatModel(JUDGE_MODEL_NAME, provider=provider)


vision_agent = Agent(
    vision_model,
    deps_type=AndroidEvidenceDeps,
    output_type=VisionAgentResult,
    system_prompt=VISION_AGENT_PROMPT,
    retries=STRUCTURED_OUTPUT_RETRIES,
)


vision_agent.tool(list_screens)


vision_agent.tool(inspect_screen)


vision_agent.tool(next_screen)


ui_event_agent = Agent(
    text_model,
    deps_type=AndroidEvidenceDeps,
    output_type=UIEventAgentResult,
    system_prompt=UI_EVENT_AGENT_PROMPT,
    retries=STRUCTURED_OUTPUT_RETRIES,
)


ui_event_agent.tool(list_screens)


ui_event_agent.tool(list_ui_events)


ui_event_agent.tool(read_ui_state)


ui_event_agent.tool(read_related_events)


ui_event_agent.tool(read_raw_ui_event)


ui_event_agent.tool(first_related_event)


ui_event_agent.tool(next_screen)


api_agent = Agent(
    text_model,
    deps_type=AndroidEvidenceDeps,
    output_type=APIAgentResult,
    system_prompt=API_AGENT_PROMPT,
    retries=STRUCTURED_OUTPUT_RETRIES,
)


api_agent.tool(list_screens)


api_agent.tool(list_events)


api_agent.tool(read_related_events)


api_agent.tool(read_api_calls)


api_agent.tool(read_raw_event)


api_agent.tool(first_related_event)


judge_agent = Agent(
    judge_model,
    deps_type=AndroidEvidenceDeps,
    output_type=AndroidMalwareAnalysisOutput,
    system_prompt=JUDGE_AGENT_PROMPT,
    retries=STRUCTURED_OUTPUT_RETRIES,
)


