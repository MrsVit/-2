import json
import logging
from typing import Dict, Any, Optional, Tuple
import httpx
from models import HeuristicResult, Verdict, SecretFinding
from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMIntegrator:
    
    def __init__(self):
        self.qwen_url = Config.QWEN_URL  # "https://qwen3.product.nova.neurotech.k2.cloud/"
        self.qwen_token = Config.QWEN_TOKEN
        self.model = Config.QWEN_MODEL  # e.g., "Qwen/Qwen2.5-7B-Instruct"
        self.confidence_threshold = Config.LLM_CONFIDENCE_THRESHOLD
        self.verify_ssl = Config.VERIFY_SSL  # Можно вынести в конфиг
        
    def analyze_with_context(self, 
                           heuristic_result: HeuristicResult,
                           context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        
        try:
            prompt = self._build_prompt(heuristic_result, context)
            
            # Вызов Qwen API
            response = self._call_qwen_api(prompt)
            
            # Парсинг ответа
            llm_result = json.loads(response)
            enriched_result = self._enrich_llm_result(llm_result, heuristic_result)
            
            logger.info(f"LLM анализ: {heuristic_result.secret[:10]}... -> {enriched_result['llm_verdict']}")
            return enriched_result
            
        except Exception as e:
            logger.error(f"Ошибка LLM анализа: {e}")
            return self._get_fallback_result(heuristic_result, str(e))
    
    def _call_qwen_api(self, prompt: str) -> str:        
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 1024,
                "temperature": 0.1,
                "top_p": 0.95,
                "do_sample": True,
                "return_full_text": False
            }
        }
        
        headers = {
            "Authorization": f"Bearer {self.qwen_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = httpx.post(
                self.qwen_url,
                headers=headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=30.0
            )
            
            response.raise_for_status()
            
            # Извлекаем сгенерированный текст из ответа
            response_json = response.json()
            
            # Формат ответа может различаться, адаптируем под разные варианты
            if isinstance(response_json, list):
                # Если ответ приходит как список
                generated_text = response_json[0].get("generated_text", "")
            elif isinstance(response_json, dict):
                # Если ответ приходит как словарь
                generated_text = response_json.get("generated_text", "")
            else:
                # Иначе пробуем получить текстовый ответ
                generated_text = str(response_json)
            
            # Убедимся, что ответ содержит JSON
            if not generated_text.strip().startswith("{"):
                # Попробуем извлечь JSON из текста, если он обернут
                import re
                json_match = re.search(r'\{.*\}', generated_text, re.DOTALL)
                if json_match:
                    generated_text = json_match.group(0)
                else:
                    raise ValueError(f"Ответ не содержит JSON: {generated_text[:200]}")
            
            return generated_text
            
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP ошибка от Qwen API: {e.response.status_code} - {e.response.text}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Ошибка подключения к Qwen API: {e}")
            raise
        except Exception as e:
            logger.error(f"Ошибка обработки ответа Qwen: {e}")
            raise
    
    def _build_prompt(self, heuristic_result: HeuristicResult, context: Dict[str, Any] = None) -> str:
        features = heuristic_result.features
        
        prompt_data = {
            "secret_preview": heuristic_result.secret[:50] + "..." if len(heuristic_result.secret) > 50 else heuristic_result.secret,
            "secret_length": len(heuristic_result.secret),
            "heuristic_verdict": heuristic_result.verdict,
            "heuristic_score": heuristic_result.score,
            "heuristic_description": heuristic_result.description,
            "features": {
                "entropy": features.get("entropy"),
                "length": features.get("length"),
                "has_placeholder": features.get("has_placeholder", False),
                "in_test_path": features.get("in_test_path", False),
                "has_dev_comment": features.get("has_dev_comment", False),
                "is_url": features.get("is_url", False)
            }
        }
        
        # Добавляем контекст, если есть
        if context:
            prompt_data.update({
                "file_path": context.get("file_path"),
                "line_number": context.get("line_number"),
                "code_context": context.get("code_context"),
                "rule_id": context.get("rule_id")
            })
        
        prompt_template = """Ты эксперт по анализу безопасности кода. Проанализируй потенциальный секрет и верни ответ ТОЛЬКО в формате JSON.

Требования к ответу:
1. Ответ должен быть ВАЛИДНЫМ JSON объектом
2. Не добавляй никакого текста кроме JSON
3. Используй точный формат ниже

ДАННЫЕ ИЗ ЭВРИСТИЧЕСКОЙ СИСТЕМЫ:
- Секрет: {secret_preview}
- Длина: {secret_length}
- Эвристический вердикт: {heuristic_verdict}
- Оценка: {heuristic_score}
- Описание: {heuristic_description}

ФИЧИ ИЗ АНАЛИЗА:
- Энтропия: {entropy}
- Длина: {length}
- Содержит placeholder: {has_placeholder}
- В тестовом пути: {in_test_path}
- Есть dev-комментарий: {has_dev_comment}
- Это URL: {is_url}

{additional_context}

ОСОБОЕ ВНИМАНИЕ:
- Энтропия {entropy} - это {'НИЗКАЯ (вероятно FP)' if entropy < 3.0 else 'ВЫСОКАЯ (вероятно TP)'}
- Если энтропия < 3.0 и нет других признаков TP - склоняйся к FP
- Если есть 'test', 'mock', 'example' в контексте - склоняйся к FP

ФОРМАТ ОТВЕТА (JSON):
{{
    "verdict": "tp" или "fp",
    "confidence": число от 0 до 1,
    "reasoning": "подробное объяснение на русском, почему такой вердикт",
    "key_factors": ["список", "ключевых", "факторов", "повлиявших", "на", "решение"],
    "agrees_with_heuristics": true или false,
    "additional_evidence": "дополнительные наблюдения",
    "recommendation_for_dev": "рекомендация разработчику"
}}
"""
        
        # Добавляем дополнительный контекст если есть
        additional_context = ""
        if context:
            additional_context = f"\nДОПОЛНИТЕЛЬНЫЙ КОНТЕКСТ:\n"
            if context.get("file_path"):
                additional_context += f"- Файл: {context['file_path']}\n"
            if context.get("code_context"):
                # Ограничиваем длину контекста
                code_context = context['code_context']
                if len(code_context) > 500:
                    code_context = code_context[:250] + "..." + code_context[-250:]
                additional_context += f"- Контекст кода: {code_context}\n"
            if context.get("rule_id"):
                additional_context += f"- Правило: {context['rule_id']}\n"
        
        # Форматируем prompt с данными
        formatted_prompt = prompt_template.format(
            secret_preview=prompt_data["secret_preview"],
            secret_length=prompt_data["secret_length"],
            heuristic_verdict=prompt_data["heuristic_verdict"],
            heuristic_score=prompt_data["heuristic_score"],
            heuristic_description=prompt_data["heuristic_description"],
            entropy=features.get("entropy", 0),
            length=features.get("length", 0),
            has_placeholder=features.get("has_placeholder", False),
            in_test_path=features.get("in_test_path", False),
            has_dev_comment=features.get("has_dev_comment", False),
            is_url=features.get("is_url", False),
            additional_context=additional_context
        )
        
        # Добавляем пример валидного JSON для лучшего понимания формата
        example_json = {
            "verdict": "fp",
            "confidence": 0.85,
            "reasoning": "Строка имеет низкую энтропию и находится в тестовом файле",
            "key_factors": ["low_entropy", "test_file"],
            "agrees_with_heuristics": True,
            "additional_evidence": "",
            "recommendation_for_dev": "Использовать mock данные в тестах"
        }
        
        formatted_prompt += f"\nПример правильного ответа (не используй этот конкретный ответ):\n{json.dumps(example_json, ensure_ascii=False)}"
        
        return formatted_prompt
    
    def _enrich_llm_result(self, llm_result: Dict[str, Any], 
                          heuristic_result: HeuristicResult) -> Dict[str, Any]:
        """Обогащение результата LLM"""
        verdict_str = llm_result.get("verdict", "").lower()
        
        # Маппинг строкового вердикта в enum
        if verdict_str == "tp":
            llm_verdict = Verdict.TRUE_POSITIVE
        elif verdict_str == "fp":
            llm_verdict = Verdict.FALSE_POSITIVE
        else:
            # Если вердикт не распознан, используем эвристический
            llm_verdict = Verdict(heuristic_result.verdict)
        
        # Проверяем согласие с эвристикой
        heuristic_verdict_str = str(heuristic_result.verdict).lower()
        agrees = (
            (verdict_str == "tp" and "true" in heuristic_verdict_str) or
            (verdict_str == "fp" and "false" in heuristic_verdict_str)
        )
        
        return {
            "llm_verdict": llm_verdict,
            "llm_confidence": float(llm_result.get("confidence", 0.5)),
            "llm_explanation": llm_result.get("reasoning", ""),
            "llm_key_factors": llm_result.get("key_factors", []),
            "llm_agrees_with_heuristics": llm_result.get("agrees_with_heuristics", agrees),
            "llm_additional_evidence": llm_result.get("additional_evidence", ""),
            "llm_recommendation": llm_result.get("recommendation_for_dev", ""),
            "raw_llm_response": llm_result
        }
    
    def _get_fallback_result(self, heuristic_result: HeuristicResult, error: str) -> Dict[str, Any]:
        """Резервный результат при ошибке"""
        return {
            "llm_verdict": Verdict.UNCERTAIN,
            "llm_confidence": 0.0,
            "llm_explanation": f"Ошибка LLM анализа: {error}. Использован эвристический вердикт.",
            "llm_key_factors": ["error_fallback"],
            "llm_agrees_with_heuristics": True,
            "llm_additional_evidence": "",
            "llm_recommendation": "Проверить вручную",
            "error": True
        }
    
    def should_use_llm(self, heuristic_result: HeuristicResult, threshold: float = None) -> bool:
        """Определяет, нужно ли использовать LLM для данного случая"""
        if threshold is None:
            threshold = self.confidence_threshold
        
        # Если оценка уверенности низкая - используем LLM
        if abs(heuristic_result.score) < threshold:
            return True
        
        features = heuristic_result.features
        has_conflicts = (
            features.get("entropy", 0) > 3.0 and  # Высокая энтропия
            features.get("in_test_path", False)   # Но в тестовом пути
        )
        
        return has_conflicts
    
    def combine_results(self, 
                       heuristic_result: HeuristicResult,
                       llm_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Объединяет результаты эвристики и LLM"""
        
        # Если нет LLM результата или низкая уверенность LLM
        if not llm_result or llm_result.get("llm_confidence", 0) < 0.6:
            return {
                "final_verdict": Verdict(heuristic_result.verdict),
                "final_confidence": abs(heuristic_result.score),
                "final_explanation": heuristic_result.description,
                "analysis_method": "heuristics_only",
                "used_llm": False
            }
        
        # Если LLM уверен и не согласен с эвристикой
        llm_confidence = llm_result.get("llm_confidence", 0)
        disagrees = not llm_result.get("llm_agrees_with_heuristics", True)
        
        if llm_confidence > 0.8 and disagrees:
            return {
                "final_verdict": llm_result.get("llm_verdict"),
                "final_confidence": llm_confidence,
                "final_explanation": llm_result.get("llm_explanation", ""),
                "analysis_method": "llm_override",
                "used_llm": True,
                "llm_agreement": False
            }
        
        # Гибридный подход: учитываем и то, и другое
        heuristic_verdict = Verdict(heuristic_result.verdict)
        llm_verdict = llm_result.get("llm_verdict")
        
        if heuristic_verdict == llm_verdict:
            # Согласованный вердикт
            avg_confidence = (abs(heuristic_result.score) + llm_confidence) / 2
            explanation = f"Согласованный вердикт. Эвристика: {heuristic_result.description}. LLM: {llm_result.get('llm_explanation', '')}"
            
            return {
                "final_verdict": heuristic_verdict,
                "final_confidence": avg_confidence,
                "final_explanation": explanation,
                "analysis_method": "hybrid_agreement",
                "used_llm": True,
                "llm_agreement": True
            }
        else:
            # Конфликт вердиктов
            heuristic_confidence = abs(heuristic_result.score)
            
            if heuristic_confidence >= llm_confidence:
                final_verdict = heuristic_verdict
                final_confidence = heuristic_confidence
                explanation = f"Конфликт вердиктов. Выбран эвристический: {heuristic_result.description}"
                method = "hybrid_heuristics_preferred"
            else:
                final_verdict = llm_verdict
                final_confidence = llm_confidence
                explanation = f"Конфликт вердиктов. Выбран LLM: {llm_result.get('llm_explanation', '')}"
                method = "hybrid_llm_preferred"
            
            return {
                "final_verdict": final_verdict,
                "final_confidence": final_confidence,
                "final_explanation": explanation,
                "analysis_method": method,
                "used_llm": True,
                "llm_agreement": False
            }


