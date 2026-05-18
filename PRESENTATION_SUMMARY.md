# LinkWatcher 발표 정리

## 1. 프로젝트 개요

**LinkWatcher**는 URL을 입력하면 `benign`, `phishing`, `defacement`, `malware` 중 하나로 분류하고, 왜 그렇게 판단했는지 XAI 형태로 설명하는 웹 기반 URL 위험 탐지 시스템이다.

초기 아이디어는 **위험 토큰 사전 기반 멀티클래스 URL 탐지**였다. 실험 과정에서 정상 URL과 피싱 URL이 문자열상 매우 유사해 단순 토큰 기반 탐지만으로는 오탐이 발생할 수 있음을 확인했고, 이를 보완하기 위해 현재는 다음 요소를 결합한 최종 통합 모듈로 구성하였다.

```text
학습 기반 위험 토큰 사전
+ URL 위치/문맥 기반 evidence
+ Transformer-token alignment
+ 정적 페이지 evidence
+ XAI 상세 설명
```

발표에서는 이를 **Learned Lexicon-Context Evidence Model** 또는 **Lexicon-Context Evidence XAI**로 설명하면 된다.

## 2. 핵심 아이디어

단순히 특정 토큰이 URL에 등장했는지만 보는 방식은 위험하다. 예를 들어 `google`, `login`, `secure`, `com` 같은 토큰은 정상 URL과 피싱 URL 양쪽에 모두 등장할 수 있다.

따라서 본 프로젝트는 다음 질문을 중심으로 최종 판단을 수행한다.

```text
그 토큰이 위험한가?
```

가 아니라,

```text
그 토큰이 URL의 위험한 위치와 문맥에서 등장했는가?
```

를 본다.

예시:

```text
https://www.google.com/
```

`google`이 실제 second-level domain 위치에 있으므로, 토큰 자체만으로 위험하게 보지 않는다.

```text
https://login-google-security.example/account/verify
```

`google`이 실제 서비스 도메인이 아니라 다른 도메인의 subdomain/path 문맥에 등장하고, `login`, `security`, `account`, `verify` 같은 credential-phishing 문맥이 함께 등장하므로 phishing evidence가 증가한다.

```text
https://www.g0ogle.com/?hl=ko
```

second-level domain에 숫자 치환이 포함되어 있고, `0 -> o` 정규화 시 `google`과 유사해지므로 look-alike impersonation evidence가 증가한다.

## 3. 최종 판정 수식

현재 최종 판정은 다음 evidence fusion score를 기반으로 한다.

```text
Risk(x) = max(
  0.40 * LearnedURLLexicon(x)
+ 0.25 * TransformerLexiconAlignment(x)
+ 0.35 * StaticPageEvidence(x),
  strong evidence floor
)
```

각 항목의 의미는 다음과 같다.

| 항목 | 의미 |
|---|---|
| `LearnedURLLexicon(x)` | 학습 데이터 기반 위험 토큰 사전과 URL 위치/문맥 규칙을 결합한 URL evidence |
| `TransformerLexiconAlignment(x)` | Transformer가 주목한 URL 토큰과 위험 사전 근거가 얼마나 정렬되는지 계산한 점수 |
| `StaticPageEvidence(x)` | HTML, form, password input, iframe, external form action, SSL 등 정적 페이지 분석 근거 |
| `strong evidence floor` | URL 또는 페이지에서 강한 위험 근거가 발견될 때 최종 점수가 과도하게 낮아지지 않도록 하는 보정 |

confidence는 100%에 쉽게 포화되지 않도록 threshold와의 거리를 기반으로 보수적으로 계산한다.

```text
Conf(x) = 0.55 + 0.35 * normalized_distance_from_threshold
```

페이지 evidence가 수집되지 않았거나 HTML 분석이 제한된 경우 confidence를 추가로 제한한다.

## 4. 현재 모듈 구조

### `app.py`

Flask 서버와 API 엔드포인트를 담당한다.

주요 역할:

- `/`에서 프론트엔드 페이지 제공
- `/api/predict`에서 URL 분석 API 제공
- 학습된 artifact 로드
- URL feature 생성
- Transformer phishing specialist 실행
- 정적 페이지 evidence 수집
- 최종 evidence decision 생성
- XAI 상세 설명 생성

주요 연결:

```text
app.py
 ├─ evidence_detector.classify_with_evidence()
 ├─ page_evidence.inspect_url_page()
 └─ xai.build_xai_explanation()
```

### `evidence_detector.py`

최종 판정 모듈이다.

주요 역할:

- 학습 기반 `risk_dict.json` 로드 및 해석
- URL 구조 분석
- 토큰 위치/문맥 기반 가중치 적용
- look-alike digit normalization 적용
- phishing / malware / defacement evidence 계산
- page evidence와 Transformer alignment를 결합해 최종 score 산출

중요한 점:

- 특정 정상 도메인을 whitelist로 두지 않는다.
- `google.com`, `naver.com`, `github.com`을 정상으로 하드코딩하지 않는다.
- 대신 유명 서비스명은 `impersonation_targets`로 사용한다.
- 이 목록은 정상 처리용이 아니라, 사칭 문맥에서 등장할 때 위험 evidence로 사용된다.

### `page_evidence.py`

정적 페이지 evidence 수집 모듈이다.

주요 역할:

- URL 접근 가능 여부 확인
- HTML 정적 분석
- title, form, password input, iframe, script, external form action 확인
- SSL 인증서 정보 확인
- defacement/malware/phishing 관련 텍스트 근거 확인

주의점:

- 페이지를 실제로 실행하거나 악성 스크립트를 수행하지 않는다.
- HTML 소스와 메타 정보 중심으로 정적 분석한다.
- `font`, `style`, `link`, `inline`, `scr` 같은 일반 HTML/CSS 저정보량 토큰은 evidence에서 제외한다.

### `xai.py`

XAI 상세 설명 모듈이다.







주요 역할:

- 토큰별 Transformer saliency 계산
- 위험 사전 점수 계산
- 유사 사례 기반 보조 설명 생성
- 최종 decision evidence 요약
- XAI 상세보기 화면에 필요한 JSON 생성

현재 XAI 화면에서 중요한 순서는 다음과 같다.

```text
1. Decision evidence graph
2. Evidence contribution graph
3. Integrated evidence score
4. Token evidence
5. Live page evidence
```

`Token evidence`는 보조 saliency view이며, 최종 판정 설명의 핵심은 `Decision evidence graph`와 `url_reasons`, `page_reasons`이다.

### `rebuild_risk_dict.py`

학습 데이터 기반 위험 토큰 사전을 다시 생성하는 스크립트이다.

주요 역할:

- URL tokenizer 적용
- label별 토큰 통계 계산
- malicious class별 위험 토큰 점수 산출
- phishing/defacement/malware seed term 및 확장자 정보 반영
- `artifacts_transformer/risk_dict.json` 재생성

### `transformer_final.py`

기존 학습 및 실험 코드이다.

주요 역할:

- `malicious_phish.csv` 기반 모델 학습
- TF-IDF + lexical feature + risk feature 구성
- character-level Transformer phishing specialist 학습
- artifact 저장
- progressive/streaming 운영환경 모사 실험

중간발표에서는 세부 학습 코드보다, 최종 시스템에서 사용되는 artifact를 만든 학습 파이프라인으로 설명하면 된다.

### `frontend/index.html`

웹 UI와 XAI 상세보기 화면을 담당한다.

주요 기능:

- URL 입력
- 분석 결과 출력
- `XAI 상세보기` 새창 표시
- evidence contribution graph
- decision evidence graph
- token evidence graph
- live page evidence 표 표시

## 5. 데이터셋 사용 관계

현재 코드 기준 데이터셋 사용은 다음과 같다.

| 데이터셋 | 역할 |
|---|---|
| `malicious_phish.csv` | 메인 멀티클래스 URL 탐지 모델과 위험 토큰 사전 학습에 사용 |
| `PhiUSIIL_Phishing_URL_Dataset.csv` | XAI 유사 사례 index 및 benign/phishing 보정 실험에 참고 |

발표에서는 다음처럼 말하는 것이 안전하다.

> 기본 멀티클래스 탐지 모델과 위험 토큰 사전은 `malicious_phish.csv` 기반으로 구성하였고, XAI 유사 사례 및 일부 benign/phishing 보정 실험에는 PhiUSIIL 데이터셋을 참고하였다.

## 6. XAI 설명 방식

XAI는 두 층으로 구성된다.

### 6.1 Decision-level XAI

최종 판단을 직접 설명하는 근거이다.

예시:

```text
Second-level domain mixes letters with look-alike digits.
Second-level domain becomes 'google' after common look-alike digit normalization.
Look-alike normalized domain matches a high-value impersonation target: google.
```

이 부분이 발표에서 가장 중요하다.

### 6.2 Token-level XAI

Transformer saliency, risk dictionary, similar case, context rule을 결합한 토큰 단위 설명이다.

수식:

```text
E_i = (0.45*A_i + 0.30*D_i + 0.25*K_i) * R_i
```

| 기호 | 의미 |
|---|---|
| `A_i` | Transformer token saliency |
| `D_i` | risk dictionary score |
| `K_i` | similar case score |
| `R_i` | context rule factor |

XAI confidence:

```text
XAI(x) = P(y|x) * mean(top-k E_i)
```

현재 구현에서는 token-level evidence가 약하게 나오는 경우를 보완하기 위해 final decision evidence score도 XAI confidence에 함께 반영한다.

## 7. 예시 결과 해석

### 정상 URL 예시

```text
https://www.google.com/?hl=ko
```

예상 해석:

```text
Final decision: benign
URL risk evidence: 낮음
Transformer alignment: 낮음
Static page evidence: 위험 근거 없음 또는 제한적
```

설명:

`google`이라는 문자열 자체를 위험하게 보지 않고, 실제 second-level domain 위치에 있으며 위험 문맥이 없으므로 benign으로 판단한다.

### Look-alike phishing 예시

```text
https://www.g0ogle.com/?hl=ko
```

예상 해석:

```text
Final decision: phishing
Main evidence:
- SLD에 문자+숫자 혼합
- 0 -> o 정규화 시 google과 유사
- impersonation target lexicon과 일치
```

발표 설명:

> 이 URL은 `g0ogle.com`처럼 second-level domain 내부에 숫자 치환이 포함되어 있고, look-alike normalization을 적용하면 `google`과 일치한다. 따라서 시스템은 이를 정상 도메인 whitelist가 아니라, 브랜드 사칭 가능성이 있는 URL 구조로 판단하여 phishing evidence를 부여한다.

### Malware 예시

```text
http://download-update.example/setup.exe
```

예상 해석:

```text
Final decision: malware
Main evidence:
- HTTP 사용
- download/update/setup 문맥
- .exe 실행 파일 확장자
```

### Defacement 예시

```text
http://school-site.example/hacked.html
```

예상 해석:

```text
Final decision: defacement
Main evidence:
- hacked term
- .html 파일명
- defacement-related URL path
```

## 8. 하드코딩/누수 관련 설명

본 시스템은 특정 정상 도메인을 whitelist로 두지 않는다.

하지 않는 것:

```text
google.com이면 benign
naver.com이면 benign
github.com이면 benign
```

하는 것:

```text
브랜드명이 사칭 문맥에서 등장하는지 확인
문자-숫자 look-alike 패턴 확인
위험 확장자 확인
credential-phishing 문맥 확인
정적 페이지 evidence 확인
```

`impersonation_targets`는 정상 도메인 목록이 아니라 **사칭 대상 브랜드 lexicon**이다.

즉:

```text
google.com을 정상으로 처리하기 위한 whitelist가 아님
g0ogle, login-google-security.example 같은 사칭형 문맥을 탐지하기 위한 seed lexicon임
```

발표 표현:

> 특정 정상 도메인을 whitelist로 처리하지 않고, 유명 서비스명을 impersonation target lexicon으로 두어 해당 토큰이 정상 등록 도메인 위치가 아닌 subdomain/path/query 또는 숫자 치환 형태로 등장할 때만 사칭 evidence로 반영하였다.

## 9. 현재 한계

현재 시스템은 중간발표 기준으로 설명 가능성과 시연 가능성은 확보했지만, 다음 한계가 있다.

- URL 문자열 기반 모델 단독으로는 정상/피싱 URL 구분이 불안정할 수 있다.
- defacement URL은 실제 데이터 분포와 예시 패턴 차이에 따라 탐지가 약할 수 있다.
- 정적 페이지 evidence는 네트워크 실패, remote disconnect, SSL 오류 등에 영향을 받는다.
- Transformer alignment가 항상 최종 판단과 강하게 일치하지는 않는다.
- 일부 seed lexicon은 도메인 지식 기반이므로 완전 자동 학습이라고 설명하면 안 된다.

발표에서는 한계를 숨기기보다 다음처럼 말하는 것이 좋다.

> 단순 URL 토큰 기반 탐지의 한계를 확인했고, 이를 보완하기 위해 토큰 위치/문맥, Transformer alignment, 정적 페이지 evidence를 결합하는 방향으로 확장하였다.

## 10. Git 관리 전략

본 프로젝트는 기능 단위로 브랜치를 생성하고, 구현이 완료되면 Pull Request를 통해 main 브랜치에 병합하는 **Feature Branch 전략**을 사용하였다.

예시 브랜치:

```text
add-river-progressive-test
add-flask-transformer-api
update-frontend-page
xai-evidence-risk-dict
feat/cleanup-current-files
```

작업 단위:

```text
모델 실험
Flask API 연동
Frontend UI 개선
XAI evidence 모듈 추가
README 및 발표자료 정리
불필요 결과 파일 정리
```

커밋 메시지는 작업 목적이 드러나도록 작성하였다.

```text
feat: 새로운 기능 추가
fix: 오류 수정
update: 기존 기능 또는 문서 수정
cleanup: 불필요 파일 정리
merge: 브랜치 병합 이력
```

발표 문장:

> 본 프로젝트는 Feature Branch 전략을 사용하여 기능 단위로 브랜치를 생성하고, 구현 완료 후 Pull Request를 통해 main 브랜치에 병합하였다. 커밋 메시지는 `feat`, `update`, `cleanup`, `merge` 등 작업 목적이 드러나도록 작성하여 모델 실험, Flask API 연동, Frontend UI 개선, XAI 모듈 추가, 최종 파일 정리 과정이 Git 이력에 남도록 관리하였다.

## 11. 실행 방법

Flask 서버 실행:

```powershell
cd C:\Users\CSOS\Desktop\졸업작품_나희\phishing-url-detection
$env:FLASK_DEBUG="1"
C:\Users\CSOS\anaconda3\python.exe -m flask --app app run
```

브라우저 접속:

```text
http://127.0.0.1:5000
```

포트 충돌 시:

```powershell
C:\Users\CSOS\anaconda3\python.exe -m flask --app app run --port 5001
```

API 테스트:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/api/predict `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"url":"https://www.g0ogle.com/?hl=ko","inspect_page":true}'
```

## 12. 발표용 핵심 문장

짧은 버전:

> 본 프로젝트는 학습 기반 위험 토큰 사전, URL 위치/문맥 규칙, Transformer-token alignment, 정적 페이지 evidence를 통합한 Lexicon-Context Evidence XAI 모델을 통해 URL의 위험도를 판단하고, 그 근거를 시각적으로 설명하는 웹 기반 보안 분석 시스템이다.

조금 긴 버전:

> 초기에는 위험 토큰 사전 기반 URL 멀티클래스 탐지를 목표로 하였으나, 정상 URL과 피싱 URL이 문자열상 매우 유사해 단순 토큰 기반 탐지만으로는 오탐이 발생할 수 있음을 확인하였다. 이를 보완하기 위해 토큰이 단순히 등장했는지가 아니라 URL의 어느 위치와 문맥에서 등장했는지를 고려하고, Transformer-token alignment와 정적 페이지 evidence를 결합하는 Learned Lexicon-Context Evidence Model로 확장하였다. 또한 XAI 상세보기 화면을 통해 decision evidence, component contribution, token evidence를 함께 제공하여 최종 판단 근거를 설명 가능하게 구성하였다.

## 13. 향후 확장 가능성

현재 구조는 URL 탐지뿐 아니라 Android malware detection에도 확장 가능하다.

URL 도메인에서:

```text
위험 URL 토큰
URL 구조
정적 페이지 evidence
```

Android 도메인에서는:

```text
위험 permission
API call sequence
Manifest evidence
DEX/string evidence
```

로 대응시킬 수 있다.

발표에서 확장 아이디어로는 다음처럼 언급하면 된다.

> 본 연구의 Lexicon-Context Evidence XAI 구조는 URL 탐지뿐 아니라 Android malware detection에서도 permission/API call sequence와 manifest evidence를 결합하는 방식으로 확장 가능하다.
