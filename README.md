# PQC 양자 내성 보안 파일 전송 시스템 (PQC Secure File Transfer System)

본 프로젝트는 양자 컴퓨터의 위협으로부터 안전한 **양자 내성 암호(Post-Quantum Cryptography, PQC)** 알고리즘을 활용한 보안 파일 전송 시스템의 프로토타입입니다. 최신 NIST 표준 암호화 알고리즘을 사용하여 데이터 전송의 기밀성, 무결성 및 송신자 인증을 보장합니다.

## 🚀 주요 특징

- **양자 내성 키 교환 (ML-KEM):** ML-KEM-768(Kyber) 알고리즘을 사용하여 양자 공격에 안전한 방식으로 세션 키를 교환합니다.
- **양자 내성 전자서명 (ML-DSA):** ML-DSA-65(Dilithium) 알고리즘을 사용하여 파일 메타데이터를 서명하고, 송신자의 신원을 인증합니다.
- **하이브리드 암호화:** PQC를 통한 키 교환 후, 성능이 검증된 AES-256-GCM 대칭키 암호화를 사용하여 실제 파일 데이터를 고속으로 암호화합니다.
- **스트리밍 기반 대용량 전송:** 파일을 청크(Chunk) 단위로 분할하여 전송함으로써 메모리 효율을 극대화하고 대용량 파일 전송을 지원합니다.
- **실시간 압축 및 무결성 검증:** zlib을 이용한 데이터 압축과 SHA-256 해시를 통한 실시간 파일 무결성 검증 기능을 포함합니다.
- **공격 시나리오 시뮬레이션:** 해시 변조, 페이로드 변조, 서명 누락 등 다양한 공격 시도에 대해 시스템이 어떻게 대응하는지 확인할 수 있는 실습 스크립트를 제공합니다.
- **성능 측정 (벤치마크):** KEM, DSA, AES-GCM 성능을 측정하고 CSV 형태로 결과 데이터를 저장할 수 있는 스크립트를 포함하고 있습니다.

## 🛠 기술 스택 및 알고리즘

- **언어:** Python 3.x
- **암호화 라이브러리:**
  - [liboqs-python](https://github.com/open-quantum-safe/liboqs-python): PQC 알고리즘(ML-KEM, ML-DSA) 지원
  - [cryptography](https://cryptography.io/): AES-GCM, HKDF(Key Derivation) 지원
- **사용 알고리즘:**
  - **KEM:** `ML-KEM-768` (NIST FIPS 203)
  - **Signature:** `ML-DSA-65` (NIST FIPS 204)
  - **Symmetric:** `AES-256-GCM`
  - **Hashing:** `SHA-256`
  - **KDF:** `HKDF-SHA256`

## 📂 프로젝트 구조

```text
.
├── server.py               # PQC 보안 서버 (파일 수신 및 검증)
├── client.py               # PQC 보안 클라이언트 (파일 암호화 및 송신)
├── utils.py                # 공통 유틸리티 (로깅, 네트워크, 암호화 함수)
├── attack/                 # 공격 시나리오 스크립트 디렉토리
│   ├── attack_hash.py      # 공격 시나리오: 해시 변조 시뮬레이션
│   ├── attack_payload.py   # 공격 시나리오: 암호문 페이로드 변조 시뮬레이션
│   └── attack_signature.py # 공격 시나리오: 전자서명 무효화 시뮬레이션
├── benchmark.py            # 암호 알고리즘 성능 측정 스크립트
├── benchmark_perform.py    # 성능 측정 및 CSV 저장 스크립트
├── liboqs/                 # liboqs C 라이브러리 (빌드 필요)
└── liboqs-python/          # liboqs Python 래퍼
```

## ⚙️ 설치 및 준비 사항

1. **의존성 라이브러리 설치:**

    ```bash
    pip install cryptography
    ```

2. **liboqs 설치:**
    본 프로젝트는 `liboqs`가 시스템에 설치되어 있어야 합니다. [liboqs 설치 가이드](https://github.com/open-quantum-safe/liboqs)를 참고하여 빌드 및 설치를 진행하세요.
3. **liboqs-python 설정:**
    `liboqs-python` 폴더 내의 라이브러리가 Python 경로에 포함되어야 합니다.

## 📖 사용 방법

### 1. 서버 실행

먼저 서버를 실행하여 클라이언트의 접속을 대기합니다.

```bash
python server.py
```

서버는 실행 후 `9999` 포트에서 대기하며, 수신된 파일은 `received_files` 디렉토리에 자동으로 저장됩니다.

### 2. 클라이언트 실행

다른 터미널에서 클라이언트를 실행합니다.

```bash
python client.py
```

실행 시 파일 선택 창(GUI)이 나타납니다. 전송할 파일을 선택하면 서버로의 안전한 전송이 시작됩니다.

### 3. 공격 시나리오 테스트

보안 메커니즘이 정상 작동하는지 확인하기 위해 `attack` 폴더 내의 공격 스크립트를 실행해 볼 수 있습니다.

- **해시 변조 공격:** `python attack/attack_hash.py`
- **페이로드 변조 공격:** `python attack/attack_payload.py`
- **서명 변조 공격:** `python attack/attack_signature.py`

### 4. 성능 벤치마크 (Benchmark)

사용된 알고리즘의 동작 속도 및 크기를 분석하고 싶다면 벤치마크 스크립트를 실행합니다.

- **기본 성능 측정 (터미널 출력):** `python benchmark.py`
- **상세 성능 측정 (CSV 파일 자동 저장 포함):** `python benchmark_perform.py`

## 📝 로그 및 모니터링

시스템의 모든 동작은 터미널에 색상별로 구분되어 출력되며, 동시에 `pqc_transfer.log` 파일에 상세히 기록됩니다.

- `[INFO]`: 일반적인 진행 상태
- `[PASS]`: 보안 검증 성공
- `[FAIL]`: 보안 검증 실패 (공격 차단)
- `[ERROR]`: 시스템 오류 또는 예외 발생

---
본 프로젝트는 교육 및 연구 목적으로 제작되었습니다.
