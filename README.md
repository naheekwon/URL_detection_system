# LinkWatcher

> 학습 기반 위험토큰 사전과 Transformer-token alignment를 결합한 URL 문맥 기반 XAI 악성 URL 탐지 시스템

<br/>

## 프로젝트 개요

**LinkWatcher**는 URL을 입력하면 `benign`, `phishing`, `defacement`, `malware` 중 하나로 분류하고, 왜 그렇게 판단했는지 설명 가능한 근거를 함께 제공하는 웹 기반 URL 위험 탐지 시스템입니다.

본 프로젝트의 핵심은 단일 모델의 확률값만 제시하는 것이 아니라, 학습 데이터에서 생성한 위험토큰 사전과 Transformer의 토큰 중요도를 함께 활용하여 URL 구조와 토큰 문맥을 설명 가능한 근거로 제시하는 것입니다.

웹 화면에서는 URL 문자열과 구조에서 관찰되는 근거를 중심으로 설명합니다.
<br/>


## 시스템 아키텍처

현재 구현된 시스템은 URL 입력, 멀티클래스 탐지, XAI 근거 생성, 대시보드 시각화로 이어지는 웹 기반 구조를 가집니다.
<br/>
<img src="frontend/architecture.png" alt="LinkWatcher detection model architecture">
<br/>

주요 처리 흐름은 다음과 같습니다.

1. Flask 백엔드가 프론트엔드에서 URL을 입력받습니다.
2. URL을 scheme, host, subdomain, path, query, file extension, 구조적 신호로 분해합니다.
3. 학습 데이터에서 생성된 `artifacts_transformer/risk_dict.json` 기반 lexicon-context evidence를 계산합니다.
4. Transformer가 중요하게 본 토큰과 위험토큰 사전의 정렬 정도를 보조 근거로 반영합니다.
5. 최종 예측 결과와 함께 한국어 XAI 요약, 판단 근거 그래프, 토큰별 설명 기여도를 제공합니다.

핵심 구현 파일은 다음과 같습니다.

- `app.py`: Flask API 및 웹 서버 진입점
- `evidence_detector.py`: URL 구조 기반 evidence 계산
- `xai.py`: XAI 설명 데이터 생성
- `frontend/index.html`: 웹 UI 및 XAI 상세 화면

## 최종 판단 기준

최종 판정은 URL 문맥 근거와 Transformer-token alignment를 결합한 evidence score를 기준으로 산출됩니다.

```text
Risk evidence(x) = f(
  LearnedURLLexicon(x),
  TransformerLexiconAlignment(x),
  strong evidence floor
)
```

각 항목의 의미는 다음과 같습니다.

- `LearnedURLLexicon(x)`: 학습 데이터에서 생성된 `artifacts_transformer/risk_dict.json` 기반 URL 위험토큰 점수
- `TransformerLexiconAlignment(x)`: Transformer가 중요하게 본 토큰이 학습 위험토큰과 얼마나 정렬되는지 나타내는 점수
- `strong evidence floor`: URL 구조에서 강한 위험 근거가 발견될 때 위험도가 과도하게 희석되지 않도록 하는 보정항

웹 데모 화면에서는 단순 확률값보다 XAI 근거를 중심으로 보여줍니다. 표시되는 evidence score는 악성 확률이 아니라, 최종 판단을 설명하기 위한 근거 강도입니다.

## XAI 출력

상세보기 화면에서는 최종 예측 결과와 함께 다음 핵심 근거를 제공합니다.

- 최종 판정 클래스
- URL 문맥 근거 강도
- 학습 위험토큰 사전 기반 근거
- Transformer-token alignment 점수
- 문맥 기반 XAI 요약
- 판단 근거 구성 비율
- 토큰별 중요도
- 유사 URL 사례
- 세부 evidence score

즉, 단순히 `phishing` 또는 `benign`만 출력하는 것이 아니라, 어떤 URL 토큰과 구조가 판정에 영향을 주었는지 함께 확인할 수 있습니다.

예를 들어 malware 샘플은 IP 기반 host와 `.exe` 실행 파일 경로가 함께 나타나는 파일 전달형 URL 문맥으로 설명하고, phishing 샘플은 인증 유도 토큰과 공식 서비스 도메인이 아닌 하위 도메인 구조의 결합 문맥으로 설명합니다. defacement 샘플은 `hacked`, `defaced`, `anonymous`처럼 변조 관련 토큰이 URL 경로 문맥에서 함께 나타나는지를 중심으로 설명합니다.

## AI 도구 활용 전략 (Prompting Log)

본 프로젝트에서는 AI 코딩 도구를 단순 코드 생성 도구가 아니라, 구현 검토와 문서화 보조 도구로 활용했습니다.

- 백엔드와 프론트엔드 브랜치 정리, GitHub main 브랜치와의 디렉토리 상태 비교, 불필요한 파일 검토에 AI를 활용했습니다.
- Flask 기반 웹 API, XAI 출력 구조, 한국어 상세 설명 UI를 개선하는 과정에서 AI에게 구현 후보와 리팩터링 방향을 제안받았습니다.
- XAI 화면에서 과도한 표현, 혼동 가능한 확률 표현, 현재 구현과 맞지 않는 설명을 찾아내고 수정했습니다.
- 발표 자료용 Git 커밋 시각화, 최종 시스템 아키텍처 설명, 클래스별 XAI 데모 문서 정리에 AI를 활용했습니다.
- Human-in-the-loop 방식으로 사용자가 최종 표현과 기능 범위를 검토했습니다. 특히 샘플 URL별 하드코딩을 피하고, 현재 구현 범위를 벗어나는 설명이 포함되지 않도록 사람이 직접 검수했습니다.

## How to run

PowerShell에서 다음 명령어로 실행할 수 있습니다.

```powershell
cd C:\Users\CSOS\Desktop\url_detection_web\phishing-url-detection
& C:\Users\CSOS\anaconda3\python.exe -m pip install -r requirements.txt
& C:\Users\CSOS\anaconda3\python.exe app.py
```

기본 실행 주소는 다음과 같습니다.

```text
http://127.0.0.1:8765
```

다른 포트로 실행하고 싶다면 `PORT` 환경변수를 지정합니다.

```powershell
$env:PORT="5000"
& C:\Users\CSOS\anaconda3\python.exe app.py
```

API는 다음 형식으로 사용할 수 있습니다.

```http
POST /api/predict
Content-Type: application/json

{
  "url": "http://example.com"
}
```

