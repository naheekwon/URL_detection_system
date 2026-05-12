# LinkWatcher

> 학습 기반 위험토큰 사전, Transformer-token alignment, 정적 페이지 evidence를 결합한 XAI 기반 악성 URL 탐지 시스템

## 프로젝트 개요

**LinkWatcher**는 URL을 입력하면 `benign`, `phishing`, `defacement`, `malware` 중 하나로 분류하고, 왜 그렇게 판단했는지 설명 가능한 근거를 함께 제공하는 웹 기반 URL 위험 탐지 시스템입니다.

본 프로젝트의 핵심은 단일 모델의 확률값만 사용하는 것이 아니라, 학습 데이터에서 생성한 위험토큰 사전과 Transformer의 토큰 중요도, 그리고 안전한 정적 페이지 분석 결과를 결합하여 최종 위험도를 산출하는 것입니다.

## 제안 모델

현재 구현된 최종 모듈은 다음과 같은 구조를 가집니다.

```text
Learned Lexicon-Context XAI Model
= 학습 기반 위험토큰 사전
+ Transformer-token alignment
+ 정적 페이지 evidence
+ XAI 상세 설명
```

각 모듈의 역할은 다음과 같습니다.

```text
rebuild_risk_dict.py
  학습 데이터 기반 risk_dict.json 재생성

artifacts_transformer/risk_dict.json
  phishing / defacement / malware별 학습 기반 위험토큰 사전

evidence_detector.py
  최종 evidence fusion score 계산 및 클래스 판정

xai.py
  Transformer saliency, 위험사전 근거, 유사 사례 기반 XAI 결과 생성

page_evidence.py
  JavaScript 실행 없이 HTML, SSL, form, script 구조를 정적으로 분석

app.py
  Flask API 서버 및 전체 모듈 연결

frontend/index.html
  URL 입력, 최종 판정, XAI 상세보기 UI 제공
```

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

## 하드코딩 Guard 사용 여부

본 시스템은 특정 정상 도메인을 whitelist로 하드코딩하여 benign으로 보정하지 않습니다.

예를 들어 다음과 같은 방식은 사용하지 않습니다.

```text
google.com이면 정상
naver.com이면 정상
github.com이면 정상
```

최종 판정은 `risk_dict.json`, Transformer-token alignment, 정적 페이지 evidence의 결합 점수로 계산됩니다.

일부 seed term은 `rebuild_risk_dict.py`에서 위험토큰 사전을 재생성할 때 반영됩니다. 이는 추론 시 특정 도메인을 정상 처리하기 위한 guard가 아니라, 학습 기반 위험토큰 사전을 보강하기 위한 사전 구축 단계의 정보입니다.

## 정적 페이지 분석 안전성

`page_evidence.py`는 URL을 실제 브라우저처럼 실행하지 않습니다.

수행하는 작업:

- 제한된 HTTP GET 요청
- HTML 소스 일부 분석
- title, form, input, iframe, script 구조 추출
- SSL 인증서 정보 확인

수행하지 않는 작업:

- JavaScript 실행
- 링크 클릭
- 파일 다운로드
- form 제출
- 사용자 입력 전송

또한 private/local IP 접근은 차단하여 내부망이나 로컬 주소로 요청이 나가지 않도록 설계했습니다.

## 실행 방법

Windows PowerShell 기준:

```powershell
cd C:\Users\CSOS\Desktop\졸업작품_나희\phishing-url-detection
$env:FLASK_DEBUG="1"
C:\Users\CSOS\anaconda3\python.exe -m flask --app app run
```

실행 후 브라우저에서 접속합니다.

```text
http://127.0.0.1:5000
```

포트가 이미 사용 중이면 다른 포트를 지정할 수 있습니다.

```powershell
C:\Users\CSOS\anaconda3\python.exe -m flask --app app run --port 5001
```

## 위험토큰 사전 재생성

`risk_dict.json`은 최종 판정의 핵심 artifact입니다. 다음 명령으로 다시 생성할 수 있습니다.

```powershell
C:\Users\CSOS\anaconda3\python.exe rebuild_risk_dict.py
```

이 스크립트는 `malicious_phish.csv`를 기반으로 `artifacts_transformer/risk_dict.json`을 재생성합니다.

재생성된 `risk_dict.json`은 다음에 사용됩니다.

- `LearnedURLLexicon(x)` 계산
- `TransformerLexiconAlignment(x)` 계산
- phishing / defacement / malware 유형별 evidence score 산출
- XAI 상세 근거 생성

## 주요 파일 구조

```text
app.py
  Flask API 서버

frontend/index.html
  웹 프론트엔드

evidence_detector.py
  evidence fusion classifier

xai.py
  XAI report generator 및 Transformer-token alignment

page_evidence.py
  안전한 정적 페이지 evidence extractor

rebuild_risk_dict.py
  학습 기반 위험토큰 사전 재생성 스크립트

transformer_final.py
  기존 River-style progressive evaluation 및 Transformer 학습 스크립트

baseline.py
  baseline / ablation 비교용 실험 스크립트

calibrate_phiusiil_meta_gate.py
  이전 calibration 실험 스크립트

artifacts_transformer/
  모델 artifact, tokenizer vocab, risk_dict.json 저장 위치
```

## 운영환경 적용 시 고려사항

현재 구현은 졸업작품 및 연구 프로토타입으로, 실제 운영환경에 바로 배포하기보다는 다음 보완이 필요합니다.

- 최신 URL threat intelligence 데이터로 `risk_dict.json` 주기적 재생성
- 실제 benign URL과 최신 phishing URL을 포함한 외부 검증셋 평가
- threshold 및 confidence calibration 추가 검증
- page evidence 요청에 대한 rate limit, timeout, sandbox 정책 강화
- 악성 URL 접근 로그와 실패 케이스를 기반으로 한 지속적 업데이트

따라서 본 시스템은 인간 전문가 없이 완전 자동 운영을 목표로 한 완성형 보안 제품이라기보다는, 분석가가 URL 위험 근거를 빠르게 확인할 수 있도록 돕는 **설명가능한 탐지 보조 시스템**에 가깝습니다.

다만 최종 판정 근거가 토큰, 사전, 페이지 evidence 단위로 분해되어 제공되므로, 기존 black-box URL 분류기보다 운영자 검토와 개선에 유리한 구조를 가집니다.
