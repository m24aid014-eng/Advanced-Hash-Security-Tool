# Advanced Hash Security Tool
Comparative study of SHA-256, SHA-3, and SHA-512 with Streamlit implementation.

## 📌 Overview
This project extends earlier work on SHA-256 and SHA-3 by incorporating SHA-512 to provide a broader comparative analysis of cryptographic hash functions.  
It evaluates original and modified versions of SHA-256 and SHA-3 alongside SHA-512 using metrics such as avalanche effect, entropy, bit distribution, Hamming distance, collision resistance, and preimage resistance.  
A custom **Streamlit app** provides interactive testing, grouped visualizations, and automated reporting.

## ⚙️ Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/m24aid014-eng/Advanced-Hash-Security-Tool.git
cd Advanced-Hash-Security-Tool
pip install -r requirements.txt
``` 

## Usage
run the streamlit app

```bash
streamlit run app.py
```
If the above doesn’t work, use:

```bash
python -m streamlit run app.py

```


## Features
Implements SHA-256 (original + modified), SHA-3 (original + modified), and SHA-512.

Calculates avalanche effect, Shannon entropy, bit distribution, and Hamming distance.

Tests collision resistance and preimage resistance.

Provides execution time scaling, grouped visualizations, and automated reporting.

Allows CSV and PNG downloads of metrics and charts.

# Results Summary
SHA-256 → fastest execution, optimized for efficiency

SHA-3 → balanced resilience with moderate speed

SHA-512 → strongest security margin but slower

## Author
G Akhila. 

M.Tech Project, IIT Jodhpur



