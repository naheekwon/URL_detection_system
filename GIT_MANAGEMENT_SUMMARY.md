# Git/GitHub 관리 이력 정리

## 1. Git 관리 전략

본 프로젝트는 `main` 브랜치에 직접 모든 작업을 반영하지 않고, 기능 단위로 별도 브랜치를 생성한 뒤 Pull Request를 통해 병합하는 **Feature Branch 전략**을 사용하였다.

기본 흐름은 다음과 같다.

```text
기능 또는 실험 단위 브랜치 생성
→ 해당 브랜치에서 구현/수정
→ GitHub에 push
→ Pull Request 생성
→ 변경 내용 확인
→ main 브랜치로 merge
```

이 방식을 통해 모델 실험, API 연동, 프론트엔드 개선, XAI 모듈 추가, 파일 정리 작업을 서로 구분하여 관리하였다.

## 2. 사용한 주요 브랜치

현재 Git 기록 기준 주요 브랜치는 다음과 같다.

| 브랜치 | 목적 |
|---|---|
| `improved-phishing-detection` | 초기 피싱 탐지 개선 작업 |
| `update-frontend-page` | 웹 프론트엔드 화면 및 인터랙션 개선 |
| `add-river-progressive-test` | River progressive 방식의 운영환경 모사 실험 |
| `add-flask-transformer-api` | Flask API 및 Transformer 기반 URL 분석 연동 |
| `xai-evidence-risk-dict` | XAI evidence 및 위험 토큰 사전 기반 설명 모듈 추가 |
| `feat/cleanup-current-files` | 불필요한 과거 실험 파일 및 결과 파일 정리 |

발표에서는 다음처럼 설명할 수 있다.

> 기능 구현, 실험, 프론트엔드 개선, XAI 추가, 파일 정리 작업을 각각 독립 브랜치로 나누어 관리하였다. 이를 통해 각 작업의 목적과 변경 범위를 Git 기록에서 분리해 추적할 수 있도록 했다.

## 3. Pull Request 병합 이력

Git 로그 기준 확인되는 주요 PR merge 이력은 다음과 같다.

```text
2026-05-05  Merge pull request #1 from naheekwon/improved-phishing-detection
2026-05-05  Merge pull request #2 from naheekwon/update-frontend-page
2026-05-06  Merge pull request #3 from naheekwon/add-river-progressive-test
2026-05-06  Merge pull request #4 from naheekwon/update-frontend-page
2026-05-07  Merge pull request #5 from naheekwon/add-flask-transformer-api
2026-05-08  Merge pull request #6 from naheekwon/add-flask-transformer-api
2026-05-11  Merge pull request #7 from naheekwon/xai-evidence-risk-dict
2026-05-12  Merge pull request #11 from naheekwon/feat/cleanup-current-files
```

이 기록을 통해 기능이 한 번에 추가된 것이 아니라, 날짜별로 단계적으로 확장되었음을 보여줄 수 있다.

## 4. 날짜별 개발 흐름

Git commit 기록을 기준으로 정리하면 다음과 같다.

| 날짜 | 주요 작업 |
|---|---|
| 2026-05-05 | README 정리, 프로젝트 설명 보완, 초기 피싱 탐지 개선 브랜치 병합 |
| 2026-05-06 | River progressive 실험 결과 추가, 실험 노트북 업데이트, 프론트엔드 애니메이션 개선 |
| 2026-05-07 | Flask Transformer API 추가, README 구조 및 아키텍처 설명 수정 |
| 2026-05-08 | PhiUSIIL meta-gate calibration 연동 실험 |
| 2026-05-11 | 학습 기반 Lexicon-XAI evidence 모델 추가 |
| 2026-05-12 | README 보완, 불필요한 과거 실험 파일 및 결과 파일 정리 |

발표용 설명:

> Git 커밋 이력을 통해 모델 실험 → API 연동 → UI 개선 → XAI 모듈 추가 → 최종 정리 순서로 프로젝트가 단계적으로 발전했음을 확인할 수 있다.

## 5. Commit Convention

커밋 메시지는 작업 목적이 드러나도록 작성하였다.

주요 패턴:

```text
feat: 새로운 기능 추가
fix: 오류 수정
update: 기존 기능 또는 문서 수정
cleanup: 불필요 파일 정리
merge: 브랜치 병합 또는 충돌 해결
```

실제 커밋 예시:

```text
feat: add Flask transformer API
feat: integrate PhiUSIIL meta-gate calibration
feat: clean up unused experiment files
Add learned lexicon XAI evidence model
Enhance frontend scroll animations
Update River progressive experiment notebook
Revise README with project overview and architecture
merge main and keep cleanup deletions
```

이러한 메시지 규칙을 통해 나중에 커밋 로그만 보더라도 어떤 기능이 언제 추가되었는지 파악할 수 있다.

## 6. Traceability

본 프로젝트에서는 주요 작업 이력이 커밋과 PR 단위로 남아 있어 변경 추적이 가능하다.

추적 가능한 예시:

| 추적 대상 | Git 이력에서 확인 가능한 내용 |
|---|---|
| 모델 실험 | River progressive 실험 노트북 및 결과 추가 커밋 |
| API 연동 | Flask Transformer API 추가 브랜치와 PR |
| 프론트엔드 개선 | `update-frontend-page` 브랜치와 애니메이션 개선 커밋 |
| XAI 추가 | `xai-evidence-risk-dict` 브랜치와 XAI evidence 모델 추가 커밋 |
| 파일 정리 | `feat/cleanup-current-files` 브랜치와 cleanup 커밋 |
| 충돌 해결 | `merge main and keep cleanup deletions` 커밋 |

특히 `feat/cleanup-current-files` 브랜치에서는 불필요한 과거 실험 파일을 정리하는 과정에서 main 브랜치와 충돌이 발생했고, 이를 merge commit으로 해결하였다. 이 이력은 파일 정리 과정과 충돌 해결 과정이 Git 기록에 남아 있음을 보여준다.

## 7. 발표에 넣기 좋은 Git 시각자료

### 7.1 GitHub Network Graph

GitHub에서 다음 경로로 확인할 수 있다.

```text
Repository > Insights > Network
```

또는:

```text
https://github.com/사용자명/레포명/network
```

이 화면은 브랜치가 생성되고 main으로 merge되는 흐름을 시각적으로 보여주기 좋다.

### 7.2 터미널 Git Graph

로컬에서 다음 명령어로 확인할 수 있다.

```powershell
cd C:\Users\CSOS\Desktop\졸업작품_나희\phishing-url-detection
git log --all --graph --decorate --oneline
```

날짜까지 포함하려면:

```powershell
git log --all --graph --decorate --date=short --pretty=format:"%h %ad %d %s"
```

이 화면을 캡처하면 브랜치와 merge 흐름을 발표자료에 넣을 수 있다.

### 7.3 Commit 빈도 이미지

현재 `reports` 폴더 아래에 Git 활동을 시각화한 PNG 자료가 생성되어 있다.

```text
reports/git_activity_images/
reports/presentation_git_visuals/
```

포함된 이미지 예시:

```text
git_activity_01_dashboard.png
git_activity_02_chart.png
git_activity_03_timeline.png
presentation_01_development_timeline.png
presentation_02_commit_branch_graph.png
presentation_03_commit_frequency.png
```

이 이미지는 PPT에 바로 삽입하여 개발 활동 빈도, 타임라인, 브랜치/커밋 흐름을 설명하는 데 사용할 수 있다.

## 8. 발표용 요약 문장

짧은 버전:

> 본 프로젝트는 Feature Branch 전략을 사용하여 기능 단위로 브랜치를 생성하고, 구현 완료 후 Pull Request를 통해 main 브랜치에 병합하였다. 커밋 메시지는 작업 목적이 드러나도록 작성하여 모델 실험, API 연동, 프론트엔드 개선, XAI 모듈 추가, 파일 정리 과정을 추적 가능한 형태로 관리하였다.

조금 긴 버전:

> GitHub를 단순 저장소가 아니라 개발 이력 관리 도구로 활용하였다. 모델 실험, Flask API 연동, 프론트엔드 개선, XAI evidence 모듈 추가, 최종 파일 정리 작업을 각각 기능 단위 브랜치로 나누어 관리하고, Pull Request를 통해 main 브랜치에 병합하였다. 또한 `feat`, `update`, `cleanup`, `merge` 등 작업 목적이 드러나는 커밋 메시지를 사용하여 어떤 기능이 언제 추가되고 수정되었는지 추적할 수 있도록 했다.

## 9. 발표 슬라이드 구성 예시

### 슬라이드 제목

```text
GitHub 기반 개발 이력 관리
```

### 본문 구성

```text
Workflow Strategy
- Feature Branch 전략 사용
- 기능별 브랜치 생성 후 Pull Request로 main 병합

Commit Convention
- feat, update, cleanup, merge 등 작업 목적 중심 커밋 메시지 작성

Traceability
- 모델 실험, API 연동, UI 개선, XAI 추가, 파일 정리 이력을 커밋 단위로 추적 가능
```

### 함께 넣을 시각자료

```text
GitHub Network Graph 캡처
또는
git log --graph 캡처
또는
reports/presentation_git_visuals 이미지
```

## 10. 확인용 명령어 모음

최근 커밋 확인:

```powershell
git log --all --date=short --pretty=format:"%ad %h %s" -20
```

브랜치 확인:

```powershell
git branch -a
```

merge commit 확인:

```powershell
git log --all --merges --date=short --pretty=format:"%ad %h %s"
```

브랜치 그래프 확인:

```powershell
git log --all --graph --decorate --oneline
```

main에 특정 커밋이 반영되었는지 확인:

```powershell
git branch -r --contains 커밋해시
```
