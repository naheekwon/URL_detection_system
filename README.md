# 🔗 LinkWatcher

> AI 기반 다중 클래스 악성 URL 탐지 웹서비스  
> Multi-Class Malicious URL Detection with Adaptive Risk Token Dictionary

<br/>

## 📌 프로젝트 개요

**LinkWatcher**는 URL 문자열을 분석하여 정상 URL과 악성 URL을 분류하는 AI 기반 URL 위험 탐지 웹서비스입니다.

본 프로젝트는 피싱, 악성코드 유포, 웹 변조 URL과 같은 웹 기반 보안 위협을 탐지하는 것을 목표로 합니다.  
단순히 URL을 정상/악성으로만 분류하는 것이 아니라, URL의 위험 유형을 세부적으로 구분하여 보안 운영자가 더 직관적으로 위협을 이해할 수 있도록 설계했습니다.

본 시스템은 Kaggle 악성 URL 데이터셋을 기반으로 학습 및 평가되었으며, URL token feature, lexical feature, TF-IDF feature, 그리고 자체적으로 구성한 **Adaptive Risk Token Dictionary**를 결합하여 URL의 위험도를 분석합니다.

또한 정상 URL과 피싱 URL이 문자열 구조상 매우 유사하다는 점을 고려하여, 기본 다중 클래스 탐지 모델에 더해 **Character-level Transformer 기반 피싱 보조 모델**을 추가했습니다.

<br/>

## 🏗️ 시스템 아키텍처

<img src="frontend/architecture.png" alt="LinkWatcher detection model architecture">

<br/>

LinkWatcher의 전체 탐지 흐름은 다음과 같습니다.

```text
URL Input
   ↓
URL Tokenization & Lexical Feature Extraction
   ↓
TF-IDF Feature + Risk Token Feature Construction
   ↓
Base Multi-Class URL Detector
   ↓
Optional Phishing Specialist
   ↓
Final URL Risk Prediction + Explanation
