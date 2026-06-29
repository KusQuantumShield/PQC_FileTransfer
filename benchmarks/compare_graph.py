import csv
import os
from pathlib import Path

import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parent
PQC_CSV = BASE_DIR / "benchmark_results.csv"
RSA_CSV = BASE_DIR / "benchmark_RSA.csv"

OUTPUT_DIR = BASE_DIR / "comparison_graphs"


def read_csv_rows(filename):
    """
    CSV 파일을 읽어 dict 리스트로 반환합니다.
    - 성능 데이터 분석 및 그래프 생성을 위한 데이터 전처리 단계입니다.
    """
    rows = []

    with open(filename, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        for row in reader:
            rows.append(row)

    return rows


def get_avg_time(rows, category, operation):
    """
    category와 operation이 일치하는 avg_time_ms 값을 찾습니다.
    - 알고리즘 성능 비교를 위해 실수형(float) 형태의 소요 시간(ms) 데이터를 추출합니다.
    """
    for row in rows:
        if row.get("category") == category and row.get("operation") == operation:
            value = row.get("avg_time_ms", "")

            if value != "":
                return float(value)

    return None


def get_value_bytes(rows, category, operation):
    """
    category와 operation이 일치하는 value_bytes 값을 찾습니다.
    - 네트워크 오버헤드 비교를 위해 정수형(int) 형태의 데이터 크기(Bytes)를 추출합니다.
    """
    for row in rows:
        if row.get("category") == category and row.get("operation") == operation:
            value = row.get("value_bytes", "")

            if value != "":
                return int(value)

    return None


def save_bar_graph(title, labels, values, ylabel, output_path, log_scale=False):
    """
    막대 그래프를 생성하고 이미지 파일로 저장합니다.
    - Matplotlib 라이브러리를 활용하며 x축 라벨(항목명)이 겹치지 않도록 회전시켜 배치합니다.
    """
    plt.figure(figsize=(9, 5))
    plt.bar(labels, values)
    plt.title(title)
    plt.ylabel(ylabel)

    if log_scale:
        plt.yscale("log")

    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

    print(f"[그래프 저장 완료] {output_path}")


def create_key_exchange_time_graph(pqc_rows, rsa_rows):
    """
    PQC와 RSA의 전체 키 교환 시간을 비교하는 그래프를 생성합니다.
    - PQC(ML-KEM)의 키 교환 시간은 키 쌍 생성, 캡슐화, 역캡슐화, HKDF 등 각 세부 연산 시간을 모두 합산합니다.
    """
    pqc_keygen = get_avg_time(pqc_rows, "KEM", "key_generation")
    pqc_encap = get_avg_time(pqc_rows, "KEM", "encapsulation")
    pqc_decap = get_avg_time(pqc_rows, "KEM", "decapsulation")
    pqc_hkdf = get_avg_time(pqc_rows, "KEM", "hkdf")

    rsa_total = get_avg_time(rsa_rows, "RSA", "total_key_exchange")

    if None in [pqc_keygen, pqc_encap, pqc_decap, pqc_hkdf, rsa_total]:
        raise ValueError("키 교환 시간 비교에 필요한 값이 CSV에서 누락되었습니다.")

    # PQC 키 교환 전체 소요 시간 (서버/클라이언트 모두 HKDF 수행하므로 2번 합산)
    pqc_total = pqc_keygen + pqc_encap + pqc_decap + (pqc_hkdf * 2)

    labels = ["PQC(ML-KEM)", "RSA"]

    values = [pqc_total, rsa_total]

    save_bar_graph(
        title="PQC vs RSA Key Exchange Time",
        labels=labels,
        values=values,
        ylabel="Average Time (ms) - Log Scale",
        output_path=OUTPUT_DIR / "pqc_vs_rsa_key_exchange_time.png",
        log_scale=True,
    )

    print()
    print("=== 키 교환 시간 비교 ===")
    print(f"PQC 전체 키 교환 시간: {pqc_total:.4f} ms")
    print(f"RSA 전체 키 교환 시간: {rsa_total:.4f} ms")


def create_key_exchange_detail_graph(pqc_rows, rsa_rows):
    """
    PQC와 RSA의 세부 키 교환 연산 시간을 비교하는 그래프를 생성합니다.
    - 각 암호 방식에서 어떤 세부 연산(예: RSA 복호화 vs PQC 역캡슐화)이 병목을 일으키는지 상세히 파악할 수 있도록 시각화합니다.
    """
    labels = [
        "PQC KeyGen",
        "PQC Encapsulation",
        "PQC Decapsulation",
        "PQC HKDF",
        "RSA KeyGen",
        "RSA Encryption",
        "RSA Decryption",
        "RSA Session Key Gen",
    ]

    values = [
        get_avg_time(pqc_rows, "KEM", "key_generation"),
        get_avg_time(pqc_rows, "KEM", "encapsulation"),
        get_avg_time(pqc_rows, "KEM", "decapsulation"),
        get_avg_time(pqc_rows, "KEM", "hkdf"),
        get_avg_time(rsa_rows, "RSA", "key_generation"),
        get_avg_time(rsa_rows, "RSA", "encryption"),
        get_avg_time(rsa_rows, "RSA", "decryption"),
        get_avg_time(rsa_rows, "RSA", "session_key_generation"),
    ]

    if any(value is None for value in values):
        raise ValueError("세부 키 교환 시간 비교에 필요한 값이 CSV에서 누락되었습니다.")

    save_bar_graph(
        title="PQC vs RSA Operation Time Detail",
        labels=labels,
        values=values,
        ylabel="Average Time (ms) - Log Scale",
        output_path=OUTPUT_DIR / "pqc_vs_rsa_operation_detail.png",
        log_scale=True,
    )


def create_size_comparison_graph(pqc_rows, rsa_rows):
    """
    PQC와 RSA의 키 및 암호문 크기를 비교하는 그래프를 생성합니다.
    - 기존 암호 체계에 비해 PQC가 갖는 네트워크 대역폭(Bandwidth) 부담을 직관적으로 보여주기 위해 작성합니다.
    """
    labels = [
        "ML-KEM Public Key",
        "ML-KEM Ciphertext",
        "ML-KEM Shared Secret",
        "RSA Public Key",
        "RSA Encrypted Session Key",
        "AES Session Key",
    ]

    values = [
        get_value_bytes(pqc_rows, "SIZE", "kem_public_key"),
        get_value_bytes(pqc_rows, "SIZE", "kem_ciphertext"),
        get_value_bytes(pqc_rows, "SIZE", "kem_shared_secret"),
        get_value_bytes(rsa_rows, "SIZE", "rsa_public_key_der"),
        get_value_bytes(rsa_rows, "SIZE", "encrypted_session_key"),
        get_value_bytes(rsa_rows, "SIZE", "session_key"),
    ]

    if any(value is None for value in values):
        raise ValueError("키 및 암호문 크기 비교에 필요한 값이 CSV에서 누락되었습니다.")

    save_bar_graph(
        title="PQC vs RSA Key and Ciphertext Size",
        labels=labels,
        values=values,
        ylabel="Size (bytes)",
        output_path=OUTPUT_DIR / "pqc_vs_rsa_size_comparison.png",
    )

    print()
    print("=== 키 및 암호문 크기 비교 ===")

    for label, value in zip(labels, values):
        print(f"{label}: {value} bytes")


def main():
    """
    비교 그래프 생성 스크립트의 진입점(Entry Point)입니다.
    PQC와 RSA의 벤치마크 결과 CSV 파일을 로드하여 비교용 막대 그래프를 생성하고 지정된 폴더에 저장합니다.
    """
    if not os.path.exists(PQC_CSV):
        raise FileNotFoundError(f"PQC CSV 파일을 찾을 수 없습니다: {PQC_CSV}")

    if not os.path.exists(RSA_CSV):
        raise FileNotFoundError(f"RSA CSV 파일을 찾을 수 없습니다: {RSA_CSV}")

    OUTPUT_DIR.mkdir(exist_ok=True)

    pqc_rows = read_csv_rows(PQC_CSV)
    rsa_rows = read_csv_rows(RSA_CSV)

    create_key_exchange_time_graph(pqc_rows, rsa_rows)
    create_key_exchange_detail_graph(pqc_rows, rsa_rows)
    create_size_comparison_graph(pqc_rows, rsa_rows)

    print("\nPQC vs RSA 비교 그래프 생성이 완료되었습니다.")


if __name__ == "__main__":
    main()
