# LinkWatcher: AI-based Multi-Class Malicious URL Detection

Graduation project for AI-based malicious URL detection with an adaptive risk-token dictionary and River-style progressive streaming evaluation.
<br/>
<br/>

## Overview

LinkWatcher is an AI-based URL risk detection project designed to classify URLs into multiple security categories, such as benign, phishing, malware, and defacement.  
The system combines URL tokenization, lexical feature extraction, TF-IDF features, and an adaptive risk-token dictionary to support explainable URL risk analysis.

Because the Kaggle malicious URL dataset does not provide real arrival timestamps, this project does not claim a real chronological stream. Instead, the dataset is converted into a reproducible pseudo-stream using a fixed random seed. The first part of the pseudo-stream is used as a warm-up phase for initial model and risk dictionary construction, while the remaining samples are processed using River-style progressive validation.

In the streaming phase, each URL batch is evaluated before it is used for model updates:

```text
predict -> metric update -> train/update

<br/>
<br/>
<img src="frontend/architecture.png" alt="LinkWatcher detection model architecture">
