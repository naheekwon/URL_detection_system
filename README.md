# LinkWatcher

> 학습 기반 위험토큰 사전, Transformer-token alignment, 정적 페이지 evidence를 결합한 XAI 기반 악성 URL 탐지 시스템

<br/>

## 프로젝트 개요

**LinkWatcher**는 URL을 입력하면 `benign`, `phishing`, `defacement`, `malware` 중 하나로 분류하고, 왜 그렇게 판단했는지 설명 가능한 근거를 함께 제공하는 웹 기반 URL 위험 탐지 시스템입니다.

본 프로젝트의 핵심은 단일 모델의 확률값만 사용하는 것이 아니라, 학습 데이터에서 생성한 위험토큰 사전과 Transformer의 토큰 중요도, 그리고 안전한 정적 페이지 분석 결과를 결합하여 최종 위험도를 산출하는 것입니다.
<br/>


## 시스템 아키텍처

현재 구현된 시스템은 URL 입력, 멀티클래스 탐지, XAI 근거 생성, 대시보드 시각화로 이어지는 웹 기반 구조를 가집니다.
<br/>
<img src="frontend/architecture.png" alt="LinkWatcher detection model architecture">
<br/>

주요 흐름은 다음과 같습니다.

1. URL 데이터셋과 URL 토큰화를 기반으로 위험 근거 통합 모듈을 구성합니다.
2. 사용자가 웹 화면에서 URL을 입력하면 Flask 백엔드가 URL을 분석합니다.
3. 멀티클래스 탐지 엔진이 `benign`, `phishing`, `malware`, `defacement` 중 하나로 분류합니다.
4. XAI 모듈은 위험토큰 사전, URL 문맥, Transformer-token alignment, 정적 페이지 evidence를 결합해 설명 근거를 생성합니다.
5. 프론트엔드는 예측 결과와 근거 그래프를 시각화합니다.

<br/>

## 제안 모델

최종 모듈은 다음 evidence를 결합합니다.

- `LearnedURLLexicon`: 학습 데이터에서 생성한 위험토큰 사전 기반 근거
- `TransformerLexiconAlignment`: Transformer가 중요하게 본 토큰과 위험토큰 사전의 정렬 정도
- `StaticPageEvidence`: HTML, form, password input, 외부 form action, SSL, defacement text 등 정적 페이지 근거
- `URL Context Rules`: 토큰 위치, 파일 확장자, IP host, 쿼리/경로 문맥 등 URL 구조 기반 보정

<br/>

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


## XAI 출력

상세보기 화면에서는 최종 예측 결과와 함께 다음 핵심 근거를 제공합니다.

- 위험 라벨 및 confidence
- 위험토큰 사전, Transformer-token alignment, 정적 페이지 evidence를 결합한 통합 근거
- 주요 토큰과 URL 문맥이 판정에 기여한 방식
- 근거별 기여도 그래프와 토큰별 설명 점수

즉, 단순히 `phishing` 또는 `benign`만 출력하는 것이 아니라, 어떤 URL 구조와 근거 조합이 판정에 영향을 주었는지 함께 확인할 수 있습니다.

<br/>


## AI 도구 활용 전략 (Prompting Log)

본 프로젝트에서는 AI 도구(Codex, ChatGPT)를 단순 코드 생성기가 아니라,  
구현 방향 검토, 오류 원인 분석, Git 관리, 디렉토리 정리, 문서화와 발표 자료 구성을 보조하는 개발 협업 도구로 활용하였다.

| 구분 | Prompting 내용 | 반영 결과 |
| --- | --- | --- |
| 백엔드 구현 보조 | Flask API 구조, URL 분석 요청/응답 JSON, XAI 상세 응답 구성에 대해 조언을 요청 | `/api/predict`, `/health`, `/api/backend-info` 흐름과 XAI JSON 응답 구조를 정리 |
| XAI 개선 | 위험토큰 단일 설명의 한계와 context-aware evidence 구조 확장 방향을 질문 | 위험 토큰, Transformer-token alignment, 정적 페이지 evidence를 결합하는 설명 구조로 개선 |
| 프론트엔드 문구 검토 | 웹 화면 문구가 실제 모델 클래스와 동작에 맞는지 검토 요청 | `Safe URL`, `Spam` 등 부정확하거나 과장된 표현을 `benign`, `phishing`, `malware`, `defacement` 기준 문구로 수정 |
| Git 관리 | 브랜치 이동, 로컬/원격 차이 확인, `feat:` 형식 커밋 메시지, push 상태 확인을 요청 | 기능별 브랜치와 커밋 히스토리를 유지하고 GitHub 반영 상태를 점검 |
| 디렉토리 정리 | 어떤 파일이 실행에 필요하고 어떤 파일이 삭제 가능한지 검토 요청 |
| 문서화 | 작업 과정에서 프로젝트 버전 관리를 위한 md 파일 문서화 | README, `PROJECT_RESULT_PRESENTATION.md`, `FINAL_ARCHITECTURE_CREATIVITY_PRESENTATION.md` 등 발표용 문서 정리 |
| GitHub commit history 요약 | 커밋 히스토리를 발표용 그래프와 정량 요약으로 정리 요청 | `git_commit/` 디렉토리에 커밋 활동 그래프 생성 요청|

특히 다음 workflow를 유지하며 AI의 제안을 검증 후 반영하였다. 

```text
Ask → AI에게 구현 후보, 오류 원인, 문서 구조, Git 관리 방향 질문
Review → 실제 코드 diff, 실행 결과, Git 상태, 프로젝트 범위 직접 검토
Apply → 필요한 수정만 선택적으로 반영
Commit → Git 기반으로 변경 이력과 작업 근거 관리
```

AI 도구의 제안은 그대로 사용하지 않고,  
실제 코드 구조, 실행 결과, GitHub 반영 상태를 확인한 뒤 프로젝트 목적에 맞는 내용만 선별하여 반영하였다.

<br/>

## 실행 방법 (How to run)

프로젝트 루트에서 필요한 패키지를 설치한 뒤 Flask 서버를 실행합니다.

```powershell
cd "C:\Users\CSOS\Desktop\url_detection_web\phishing-url-detection"
C:\Users\CSOS\anaconda3\python.exe -m pip install -r requirements.txt
C:\Users\CSOS\anaconda3\python.exe app.py
```

브라우저에서 다음 주소로 접속합니다.

```text
http://127.0.0.1:8765
```

만약 8765 포트가 이미 사용 중이면 다음처럼 다른 포트를 지정할 수 있습니다.

```powershell
$env:PORT="8766"
C:\Users\CSOS\anaconda3\python.exe app.py
```

같은 네트워크의 다른 PC에서 접속할 경우, 실행 PC의 IPv4 주소를 확인한 뒤 다음 형식으로 접속합니다.

```text
http://<실행 PC의 IPv4 주소>:8765
```
<br/>

## 현재 한계

- 다운로드 파일의 실제 바이너리 내용은 분석하지 않습니다.
- JavaScript 실행 후 동적으로 변하는 페이지는 완전 분석하지 않습니다.
- live page evidence는 네트워크 상태, 차단, DNS 실패, HTTP 오류에 영향을 받을 수 있습니다.

