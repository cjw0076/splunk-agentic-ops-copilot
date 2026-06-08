# Splunk Incident Copilot Fallback Plan

## Objective

Splunk/Partner MCP 접근이 즉시 되지 않을 경우에도 제출 전 준비 손실을 최소화하기 위한 증빙형 데모 플랜.

## 1) Live path (우선)
- Splunk 계정/라이선스/MCP 자격 확보
- 최소 1회 트레이스 실행 증빙
- 데모 시나리오를 실제 수집 데이터 또는 샘플 로그로 캡처

## 2) Synthetic fallback
- 공개 가능한 형식으로 “사례형 로그 + 조사 트랜스크립트”만 재현 가능
- `agentic_ops` 스타일로 증거 타임라인을 문서로 출력
- 제약: 실제 운영 데이터가 아닌 합성 데이터임을 명시

## 3) 출품 준비 체크리스트
- 규칙 페이지 확인
- 제출 항목 형식 체크
- 파트너 MCP/도구 사용 근거(있으면) 또는 사용불가 사유
- 데모 링크/스크립트

## 4) 실패 모드 처리

- 라이선스/토큰 미보유
  - `operator_gate`로 명시 분기
  - synthetic transcript + 개선 계획으로 패키지 선행

- 설치/네트워크 이슈
  - 증빙 경로(`receipt`)에 에러 로그/캡처 링크만 기록
  - 실환경 재시도는 블로커 해결 시 수행

## Evidence-safe outputs (우선 작성)
- `docs/TODO.md`
- `docs/AGENT_WORKLOG.md`
- `receipts`
- `synthetic`/`timeline` 기반 단일 문서 데모 템플릿
