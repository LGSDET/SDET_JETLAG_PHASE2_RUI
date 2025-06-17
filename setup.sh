#!/bin/bash
# 프로젝트 자동 설정 스크립트

# 프로젝트 디렉토리로 이동
cd /Users/jawsmacair/Downloads/CMU/SEC_Phase2/SEC2_TripleS_RUI

# 가상환경 활성화 (가상환경 이름에 맞게 수정하세요)
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "✅ 가상환경 'venv' 활성화됨"
elif [ -d "myproject_env" ]; then
    source myproject_env/bin/activate
    echo "✅ 가상환경 'myproject_env' 활성화됨"
else
    echo "❌ 가상환경을 찾을 수 없습니다. 먼저 가상환경을 생성하세요:"
    echo "python3 -m venv venv"
fi

# 현재 Python 경로 확인
echo "현재 Python: $(which python)"
echo "현재 디렉토리: $(pwd)" 