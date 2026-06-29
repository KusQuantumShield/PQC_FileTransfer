FROM ubuntu:latest

# 설치 중 사용자 입력 대기 방지
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# 시스템 업데이트 및 필수 패키지 설치
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    wget \
    vim \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /app

# 가상 환경 생성 및 PATH 설정
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 프로젝트 파일들을 컨테이너 내부로 복사
COPY . /app

# pip 업데이트 및 Python 의존성 설치
RUN pip install --upgrade pip uv && pip install -e ".[dev]"

# 기본 명령어 설정
CMD ["/bin/bash"]
