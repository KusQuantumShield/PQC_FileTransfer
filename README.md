# PQC 양자 내성 보안 파일 전송 시스템 (PQC Secure File Transfer System)

본 프로젝트는 양자 컴퓨터의 위협으로부터 안전한 **양자 내성 암호(Post-Quantum Cryptography, PQC)** 알고리즘을 활용한 보안 파일 전송 시스템의 프로토타입입니다. 최신 NIST 표준 암호화 알고리즘을 사용하여 데이터 전송의 기밀성, 무결성 및 송신자 인증을 보장합니다.

## 🚀 주요 특징

- **양자 내성 키 교환 (ML-KEM):** ML-KEM-768(Kyber) 알고리즘을 사용하여 양자 공격에 안전한 방식으로 세션 키를 교환합니다.
- **양자 내성 전자서명 (ML-DSA):** ML-DSA-65(Dilithium) 알고리즘을 사용하여 파일 메타데이터를 서명하고, 송신자의 신원을 인증합니다.
- **하이브리드 암호화:** PQC를 통한 키 교환 후, 성능이 검증된 AES-256-GCM 대칭키 암호화를 사용하여 실제 파일 데이터를 고속으로 암호화합니다.
- **스트리밍 기반 대용량 전송:** 파일을 청크(Chunk) 단위로 분할하여 전송함으로써 메모리 효율을 극대화하고 대용량 파일 전송을 지원합니다.
- **실시간 압축 및 무결성 검증:** zlib을 이용한 데이터 압축과 SHA-256 해시를 통한 실시간 파일 무결성 검증 기능을 포함합니다.
- **CLI / TUI 인터페이스 제공:** 간단한 명령어 기반의 CLI와 방향키 및 엔터만으로 손쉽게 조작 가능한 터미널 UI(TUI)를 모두 지원합니다.
- **공격 시나리오 시뮬레이션:** 해시 변조, 페이로드 변조, 서명 누락 등 다양한 공격 시도에 대해 시스템이 어떻게 대응하는지 확인할 수 있는 실습 스크립트를 제공합니다.
- **성능 측정 (벤치마크):** KEM, DSA, AES-GCM 성능을 측정하고 CSV 형태로 결과 데이터를 저장할 수 있는 스크립트를 포함하고 있습니다.

## 🛠 기술 스택 및 알고리즘

- **언어:** Python 3.9+
- **암호화 라이브러리:**
  - [liboqs-python](https://github.com/open-quantum-safe/liboqs-python): PQC 알고리즘(ML-KEM, ML-DSA) 지원
  - [cryptography](https://cryptography.io/): AES-GCM, HKDF(Key Derivation) 지원
- **사용 알고리즘:**
  - **KEM:** `ML-KEM-768` (NIST FIPS 203)
  - **Signature:** `ML-DSA-65` (NIST FIPS 204)
  - **Symmetric:** `AES-256-GCM`
  - **Hashing:** `SHA-256`
  - **KDF:** `HKDF-SHA256`

## 📂 프로젝트 구조 (src layout)

유지보수 및 확장을 위해 파이썬 표준 패키지 구조(src layout)로 구성되어 있습니다. 코어 로직과 프로토콜, UI 등이 명확히 분리되었습니다.

```text
PQC_FileTransfer/
├── pyproject.toml         # 패키지 빌드 및 설정 메타데이터
├── requirements.txt       # 의존성 패키지 목록
├── src/
│   └── pqc_transfer/      # 메인 패키지
│       ├── core/          # PQC 서버 및 클라이언트 핸들러 로직 (server.py, client.py)
│       ├── protocol/      # 프로토콜 세부 구현 (handshake, metadata, signature, chunk 등)
│       ├── ui/            # 터미널 사용자 인터페이스 (TUI) 및 파일 선택기 GUI 등
│       ├── utils/         # 기능별 분리된 유틸리티 패키지 (config, crypto, network 등)
│       ├── cli.py         # 커맨드라인 인터페이스 (CLI) 진입점 로직
│       └── exceptions.py  # 예외 처리 클래스
├── attack/                # 공격 기법 시뮬레이션 스크립트
├── benchmarks/            # 암호 알고리즘 성능 측정 벤치마크
├── tests/                 # 무결성/인증 오류 검증용 테스트 스크립트
├── liboqs/                # liboqs C 라이브러리 소스
└── liboqs-python/         # liboqs Python 래퍼
```

## ⚙️ 설치 및 준비 사항

1. **의존성 라이브러리 설치:**
    프로젝트 폴더에서 다음 명령어로 필수 패키지를 설치하고 현재 패키지를 설치합니다.
    ```bash
    pip install -r requirements.txt
    pip install -e .
    ```

2. **liboqs 설치:**
    본 프로젝트는 `liboqs`가 시스템에 설치되어 있어야 합니다. [liboqs 설치 가이드](https://github.com/open-quantum-safe/liboqs)를 참고하여 빌드 및 설치를 진행하세요.

3. **liboqs-python 설정:**
    `liboqs-python` 폴더 내의 라이브러리가 Python 경로에 포함되어야 합니다. (또는 `pip install -e .` 과정에서 설치됩니다)

## 📖 사용 방법

본 프로젝트는 설치 후 `pqc-tui`, `pqc-server`, `pqc-client` 등의 명령어(Entry point)를 통해 간편하게 실행할 수 있습니다.

### 1. 통합 터미널 UI (TUI)로 실행하기 [권장]

가장 편리하게 시스템을 테스트할 수 있는 방식입니다. 아래 명령어를 실행하면 방향키로 조작할 수 있는 직관적인 TUI가 나타납니다.

```bash
pqc-tui
```
이 화면에서 서버 구동, 클라이언트 구동(파일 선택 포함), 벤치마크 실행을 모두 쉽게 관리하고 실시간 색상 로그를 확인할 수 있습니다.

### 2. CLI 명령어로 실행하기

CLI 환경이나 백그라운드 구동을 원하실 경우, 개별 명령어를 실행할 수 있습니다.

**서버 실행:**
```bash
pqc-server
# 또는
python -m pqc_transfer server
```
서버는 실행 후 기본 `9999` 포트에서 대기하며, 수신된 파일은 `received_files` 디렉토리에 자동으로 저장됩니다.

**클라이언트 실행:**
다른 터미널 창을 열고 전송할 파일의 경로를 지정하여 실행합니다.
```bash
pqc-client <전송할_파일_경로>
# 또는
python -m pqc_transfer client <전송할_파일_경로>
```

### 3. 공격 시나리오 및 테스트

보안 메커니즘이 정상 작동하는지 확인하기 위해 `attack` 및 `tests` 폴더 내의 스크립트를 실행해 볼 수 있습니다.

- **해시 변조 공격:** `python attack/attack_hash.py`
- **페이로드 변조 공격:** `python attack/attack_payload.py`
- **서명 변조 공격:** `python attack/attack_signature.py`
- **pytest 기반 테스트:** `pytest tests/` (또는 개별 테스트 파일 실행)

### 4. 성능 벤치마크 (Benchmark)

사용된 알고리즘의 동작 속도 및 크기를 분석하고 싶다면 `benchmarks` 디렉토리 내의 스크립트를 실행합니다.

- **기본 성능 측정 (터미널 출력):** `python benchmarks/benchmark.py`
- **상세 성능 측정 (CSV 파일 저장 포함):** `python benchmarks/benchmark_perform.py`
- **기존 RSA/ECC 성능 측정 (비교용):** `python benchmarks/benchmark_RSA.py`
- **성능 비교 그래프 생성:** `python benchmarks/Compare_graph.py`

## 📝 로그 및 모니터링

시스템의 모든 동작은 터미널에 색상별로 구분되어 출력되며, 동시에 `pqc_transfer.log` 파일에 상세히 기록됩니다. (로그 파일 사이즈 초과 시 자동으로 롤링 백업됩니다)

- `[INFO]`: 일반적인 진행 상태
- `[PASS]`: 보안 검증 성공
- `[FAIL]`: 보안 검증 실패 (공격 차단)
- `[ERROR]`: 시스템 오류 또는 예외 발생

---
본 프로젝트는 양자 내성 암호 도입을 위한 교육 및 연구 목적으로 제작되었습니다.
