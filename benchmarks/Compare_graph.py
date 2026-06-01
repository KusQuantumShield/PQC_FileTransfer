import csv
import os
from pathlib import Path

import matplotlib.pyplot as plt


PQC_CSV = "Benchmark Results.csv"
RSA_CSV = "benchmark_RSA.csv"

OUTPUT_DIR = Path("comparison_graphs")


def read_csv_rows(filename):
    """
    CSV 파일을 읽어 dict 리스트로 반환합니다.
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
    """
    for row in rows:
        if row.get("category") == category and row.get("operation") == operation:
            value = row.get("value_bytes", "")

            if value != "":
                return int(value)

    return None


def save_bar_graph(title, labels, values, ylabel, output_path):
    """
    막대 그래프를 생성하고 이미지 파일로 저장합니다.
    """
    plt.figure(figsize=(9, 5))
    plt.bar(labels, values)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

    print(f"[그래프 저장 완료] {output_path}")


def create_key_exchange_time_graph(pqc_rows, rsa_rows):
    """
    PQC와 RSA의 전체 키 교환 시간을 비교하는 그래프를 생성합니다.
    """
    pqc_keygen = get_avg_time(pqc_rows, "KEM", "key_generation")
    pqc_encap = get_avg_time(pqc_rows, "KEM", "encapsulation")
    pqc_decap = get_avg_time(pqc_rows, "KEM", "decapsulation")
    pqc_hkdf = get_avg_time(pqc_rows, "KEM", "hkdf")

    rsa_total = get_avg_time(rsa_rows, "RSA", "total_key_exchange")

    if None in [pqc_keygen, pqc_encap, pqc_decap, pqc_hkdf, rsa_total]:
        raise ValueError("키 교환 시간 비교에 필요한 값이 CSV에서 누락되었습니다.")

    pqc_total = pqc_keygen + pqc_encap + pqc_decap + pqc_hkdf

    labels = [
        "PQC(ML-KEM)",
        "RSA"
    ]

    values = [
        pqc_total,
        rsa_total
    ]

    save_bar_graph(
        title="PQC vs RSA Key Exchange Time",
        labels=labels,
        values=values,
        ylabel="Average Time (ms)",
        output_path=OUTPUT_DIR / "pqc_vs_rsa_key_exchange_time.png"
    )

    print()
    print("=== 키 교환 시간 비교 ===")
    print(f"PQC 전체 키 교환 시간: {pqc_total:.4f} ms")
    print(f"RSA 전체 키 교환 시간: {rsa_total:.4f} ms")


def create_key_exchange_detail_graph(pqc_rows, rsa_rows):
    """
    PQC와 RSA의 세부 키 교환 연산 시간을 비교하는 그래프를 생성합니다.
    """
    labels = [
        "PQC KeyGen",
        "PQC Encapsulation",
        "PQC Decapsulation",
        "PQC HKDF",
        "RSA KeyGen",
        "RSA Encryption",
        "RSA Decryption",
        "RSA Session Key Gen"
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
        ylabel="Average Time (ms)",
        output_path=OUTPUT_DIR / "pqc_vs_rsa_operation_detail.png"
    )


def create_size_comparison_graph(pqc_rows, rsa_rows):
    """
    PQC와 RSA의 키 및 암호문 크기를 비교하는 그래프를 생성합니다.
    """
    labels = [
        "ML-KEM Public Key",
        "ML-KEM Ciphertext",
        "ML-KEM Shared Secret",
        "RSA Public Key",
        "RSA Encrypted Session Key",
        "AES Session Key"
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
        output_path=OUTPUT_DIR / "pqc_vs_rsa_size_comparison.png"
    )

    print()
    print("=== 키 및 암호문 크기 비교 ===")

    for label, value in zip(labels, values):
        print(f"{label}: {value} bytes")


def main():
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