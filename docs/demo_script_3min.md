# 3분 Splunk Incident Copilot 데모 스크립트 (Fallback)

## 0:00 - 0:30

- 목표 요약: Splunk/partner MCP 미접속 상태에서는 합성 로그 기반 감사형 데모를 정지 없이 유지.
- 데모 산출물: `incident_demo_fallback_plan.md`, `AGENT_WORKLOG.md`, evidence ledger 규격

## 0:30 - 1:40

- 증거 1개 프레임: `agent_evidence_ledger_schema`와 유사한 타임라인 항목 설명
- `case_id`와 `status` 전이가 어떻게 검증 지표로 바뀌는지 표시

## 1:40 - 2:30

- 합성 사고 타임라인을 읽어 “탐지 -> 분석 -> 대응 -> 검증” 4단계 전환
- 각 단계에 대해 필요한 Splunk 검색 호출 포인트(라이브 접속 전제)와 fallback 상태 구분

## 2:30 - 3:00

- 게이트 메시지:
  - `SPLUNK_TOKEN` / MCP / 라이선스 준비 시점
  - 데모 스크립트의 Live Path 전환 조건

