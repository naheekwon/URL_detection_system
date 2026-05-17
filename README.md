# LinkWatcher

> 학습 기반 위험토큰 사전, Transformer-token alignment, 정적 페이지 evidence를 결합한 XAI 기반 악성 URL 탐지 시스템

<br/>

## 프로젝트 개요

**LinkWatcher**는 URL을 입력하면 `benign`, `phishing`, `defacement`, `malware` 중 하나로 분류하고, 왜 그렇게 판단했는지 설명 가능한 근거를 함께 제공하는 웹 기반 URL 위험 탐지 시스템입니다.

본 프로젝트의 핵심은 단일 모델의 확률값만 사용하는 것이 아니라, 학습 데이터에서 생성한 위험토큰 사전과 Transformer의 토큰 중요도, 그리고 안전한 정적 페이지 분석 결과를 결합하여 최종 위험도를 산출하는 것입니다.
<br/>


## 제안 모델

현재 구현된 최종 모듈은 다음과 같은 구조를 가집니다.


## 최종 위험도 수식

최종 판정은 다음 evidence fusion score를 기준으로 산출됩니다.

```text
Risk(x) = max(
  0.40 * LearnedURLLexicon(x)
+ 0.25 * TransformerLexiconAlignment(x)
+ 0.35 * StaticPageEvidence(x),
  strong evidence floor
)
```

각 항목의 의미는 다음과 같습니다.

- `LearnedURLLexicon(x)`: 학습 데이터에서 생성된 `risk_dict.json` 기반 URL 위험토큰 점수
- `TransformerLexiconAlignment(x)`: Transformer가 중요하게 본 토큰이 학습 위험토큰과 얼마나 정렬되는지 나타내는 점수
- `StaticPageEvidence(x)`: HTML, form, password input, 외부 form action, SSL, defacement text 등 정적 페이지 근거 점수
- `strong evidence floor`: URL 또는 페이지에서 강한 위험 근거가 발견될 때 위험도가 과도하게 희석되지 않도록 하는 보정항

confidence는 100%로 과확신하지 않도록 threshold로부터의 거리를 기반으로 보수적으로 계산합니다.

```text
Conf(x) = 0.55 + 0.35 * normalized_distance_from_threshold
```

페이지 evidence가 수집되지 않았거나 HTML 분석이 제한된 경우 confidence는 추가로 제한됩니다.

## XAI 출력

상세보기 화면에서는 다음 정보를 제공합니다.

- 최종 판정 클래스
- 최종 위험도와 confidence
- 학습 위험토큰 사전 기반 근거
- Transformer-token alignment 점수
- 정적 페이지 evidence
- 토큰별 중요도
- 유사 URL 사례
- 제안 수식과 세부 score

즉, 단순히 `phishing` 또는 `benign`만 출력하는 것이 아니라, 어떤 URL 토큰과 페이지 구조가 판정에 영향을 주었는지 함께 확인할 수 있습니다.


