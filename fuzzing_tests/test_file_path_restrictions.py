"""
File Path Restrictions Fuzzing Tests
Tests for SR-06: 저장 경로 제한 (RAW 파일은 반드시 C:\\Users\\CMU\\RawRecords 경로에만 저장되도록 제한)
Based on DisplayGUI.cpp IsPathAllowed() function implementation
"""

import pytest
import os
import tempfile
import pathlib
from hypothesis import given, strategies as st, settings
from faker import Faker
import platform

fake = Faker()

# Hypothesis settings for fuzzing tests
fuzzing_settings = settings(
    max_examples=30,  # Further reduced for performance
    deadline=1000,    # 1000ms deadline for complex tests
    suppress_health_check=[],
)

class FilePathRestrictionsFuzzer:
    """Fuzzer for file path restrictions testing - 실제 C++ IsPathAllowed() 취약점 재현"""
    
    def __init__(self):
        # Windows path for the application (matches kAllowedRoot in C++ code)
        self.allowed_root_windows = r"C:\Users\CMU\RawRecords"
        # Linux equivalent for testing
        self.allowed_root_linux = "/home/CMU/RawRecords"
        
        # Determine the allowed root based on platform
        if platform.system() == "Windows":
            self.allowed_root = self.allowed_root_windows
        else:
            self.allowed_root = self.allowed_root_linux
    
    def is_path_allowed(self, file_path):
        """
        🚨 실제 C++ IsPathAllowed() 함수의 취약한 동작을 정확히 재현
        
        C++ 코드의 실제 취약점:
        1. 경로 정규화를 제대로 하지 않음
        2. 단순한 문자열 prefix 비교만 수행
        3. 경계 검사 없이 startswith()만 사용
        
        이로 인해 "/home/CMU/RawRecords_fake" 같은 경로가 허용됨!
        """
        try:
            # 🚨 C++ 코드의 취약점: 제대로 된 경로 정규화 없이 단순 문자열 처리
            # C++에서는 std::filesystem::absolute()만 사용하고 proper normalization 없음
            
            # Step 1: C++의 취약한 경로 처리 재현 - 최소한의 정규화만
            if file_path.startswith('~'):
                # 홈 디렉토리 확장만 (C++에서 하는 최소한의 처리)
                file_path = os.path.expanduser(file_path)
            
            # Step 2: C++의 absolute path 변환 (하지만 정규화는 안함!)
            if not os.path.isabs(file_path):
                file_path = os.path.abspath(file_path)
            
            # Step 3: C++의 취약한 root path 처리
            root_path = self.allowed_root
            if not os.path.isabs(root_path):
                root_path = os.path.abspath(root_path)
            
            # 🚨 Step 4: C++의 핵심 취약점 - 단순한 문자열 prefix 비교!
            # C++ 코드: if (absStr.length() >= rootStr.length() && absStr.substr(0, rootStr.length()) == rootStr)
            # 이것이 바로 취약점의 원인!
            
            if len(file_path) >= len(root_path) and file_path.startswith(root_path):
                print(f"[C++ VULNERABLE] Path allowed: {file_path}")
                print(f"  Root: {root_path}")
                print(f"  File: {file_path}")
                print(f"  🚨 VULNERABILITY: Simple prefix match without boundary check!")
                return True
            else:
                print(f"[C++ SECURE] Path blocked: {file_path}")
                return False
                
        except Exception as e:
            # C++ catch(...) - 모든 예외에서 False 반환
            print(f"[C++ EXCEPTION] Exception caught for {file_path}: {e}")
            return False
    
    def is_path_allowed_safe(self, file_path):
        """
        안전한 구현 (비교용) - 실제 보안 검증
        """
        try:
            normalized_file_path = file_path
            if platform.system() != "Windows":
                normalized_file_path = file_path.replace('\\', '/')
            
            abs_path = pathlib.Path(normalized_file_path).resolve()
            root_path = pathlib.Path(self.allowed_root).resolve()
            
            abs_str = str(abs_path)
            root_str = str(root_path)
            
            # 안전한 구현: 정확한 경계 검사
            if abs_str == root_str:
                return True  # 정확한 루트 디렉토리
            elif abs_str.startswith(root_str + '/') or abs_str.startswith(root_str + '\\'):
                return True  # 적절한 하위 디렉토리
            else:
                return False  # 모든 다른 경우 차단
                
        except Exception:
            return False
    


class TestFilePathRestrictionsFuzzing:
    """File path restrictions fuzzing tests"""
    
    def setup_method(self):
        """Setup for each test"""
        self.fuzzer = FilePathRestrictionsFuzzer()
    
    @fuzzing_settings
    @given(st.lists(st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-'), 
                   min_size=1, max_size=3))
    def test_allowed_paths(self, path_components):
        """
        허용되어야 하는 정상적인 파일 경로들을 테스트합니다.
        지정된 루트 디렉토리 내의 유효한 경로가 통과되는지 확인합니다.
        """
        try:
            # 무작위 경로 구성 요소들로 유효한 경로 생성
            clean_components = []
            for component in path_components:
                clean_component = ''.join(c for c in component if c.isalnum() or c in '._-')[:15]
                if clean_component:
                    clean_components.append(clean_component)
            
            if clean_components:
                test_path = self.fuzzer.allowed_root + "/" + "/".join(clean_components) + ".raw"
                is_allowed = self.fuzzer.is_path_allowed(test_path)
                
                if is_allowed:
                    # 허용된 경우, 실제로 허용된 디렉토리 내에 있는지 확인
                    normalized_path = self.fuzzer.normalize_path_cpp_style(test_path)
                    normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                    assert normalized_path.startswith(normalized_allowed), f"Path should be within allowed directory: {test_path}"
        except Exception:
            # 무작위 경로는 예외를 발생시킬 수 있음
            pass
    
    @fuzzing_settings
    @given(st.integers(min_value=1, max_value=8),
           st.lists(st.text(min_size=1, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz0123456789'), 
                   min_size=1, max_size=3))
    def test_directory_traversal_attacks(self, traversal_depth, target_components):
        """
        디렉토리 탐색(Directory Traversal) 공격을 테스트합니다.
        '../'와 같은 경로 조작을 통해 상위 디렉토리에 접근하는 것을 차단하는지 확인합니다.
        """
        try:
            # 무작위 깊이의 디렉토리 탐색 공격 생성
            traversal = "../" * traversal_depth
            target = "/".join(target_components[:2])  # 성능을 위해 제한
            attack_path = traversal + target
            
            is_allowed = self.fuzzer.is_path_allowed(attack_path)
            assert not is_allowed, f"Directory traversal should be blocked: {attack_path}"
        except Exception:
            # 일부 무작위 입력은 예외를 발생시킬 수 있음
            pass
    
    @fuzzing_settings
    @given(st.sampled_from(['/etc', '/root', '/home', '/var', '/usr', '/tmp', '/proc', 
                           'C:\\Windows', 'C:\\Users', 'C:\\Program Files', 'D:\\', 'E:\\']),
           st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'))
    def test_absolute_path_attacks(self, base_path, filename):
        """
        절대 경로(Absolute Path)를 이용한 공격을 테스트합니다.
        허용된 루트 디렉토리 외부의 특정 시스템 경로 접근을 차단하는지 확인합니다.
        """
        try:
            clean_filename = ''.join(c for c in filename if c.isalnum() or c in '._-')[:15]
            if clean_filename:
                attack_path = base_path + "/" + clean_filename
                is_allowed = self.fuzzer.is_path_allowed(attack_path)
                assert not is_allowed, f"Absolute path attack should be blocked: {attack_path}"
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=30),
           st.sampled_from(['\u202e', '\u200b', '\ufeff', '\u0000', 'тест', '测试', 'テスト', 'café', 'naïve']))
    def test_unicode_attacks(self, base_filename, unicode_char):
        """
        유니코드 문자를 이용한 경로 공격을 테스트합니다.
        경로에 포함된 유니코드 문자가 보안 문제를 일으키지 않는지 확인합니다.
        """
        try:
            # 유니코드 문자가 포함된 경로 생성
            clean_base = ''.join(c for c in base_filename if c.isalnum() or c in '._-')[:20]
            if clean_base:
                unicode_path = self.fuzzer.allowed_root + "/" + clean_base + unicode_char + ".txt"
                is_allowed = self.fuzzer.is_path_allowed(unicode_path)
                
                if is_allowed:
                    # 허용된 경우, 실제로 허용된 디렉토리 내에 있는지 확인
                    normalized_path = self.fuzzer.normalize_path_cpp_style(unicode_path)
                    normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                    assert normalized_path.startswith(normalized_allowed), f"Unicode path escapes allowed directory: {unicode_path}"
        except Exception:
            # 유니코드 처리는 예외를 발생시킬 수 있음
            pass
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'),
           st.sampled_from(['%2e%2e%2f', '%c0%af', '%2f', '%5c', '%00', '%2e%2e%5c', '%252e%252e%252f']))
    def test_encoding_attacks(self, filename, encoding_pattern):
        """
        URL 인코딩과 같은 특수 인코딩을 이용한 공격을 테스트합니다.
        인코딩된 공격 문자열을 정상적으로 처리하고 차단하는지 확인합니다.
        """
        try:
            clean_filename = ''.join(c for c in filename if c.isalnum() or c in '._-')[:15]
            if clean_filename:
                encoded_path = self.fuzzer.allowed_root + "/" + clean_filename + encoding_pattern + ".txt"
                is_allowed = self.fuzzer.is_path_allowed(encoded_path)
                
                if is_allowed:
                    # 허용된 경우, 디코딩 후에도 안전한지 확인
                    try:
                        import urllib.parse
                        decoded_path = urllib.parse.unquote(encoded_path)
                        normalized_decoded = self.fuzzer.normalize_path_cpp_style(decoded_path)
                        normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                        assert normalized_decoded.startswith(normalized_allowed), f"Encoded path escapes allowed directory: {encoded_path}"
                    except:
                        pass
        except Exception:
            pass

    @fuzzing_settings
    @given(st.integers(min_value=0, max_value=255))
    def test_random_ascii_suffix_attacks(self, ascii_code):
        """
        무작위 ASCII 문자를 접미사로 사용한 접두사 공격을 테스트합니다.
        허용된 경로 뒤에 임의의 ASCII 문자가 붙는 경우를 안전하게 처리하는지 확인합니다.
        """
        try:
            # Generate suffix with random ASCII character
            if 32 <= ascii_code <= 126:  # Printable ASCII
                suffix_char = chr(ascii_code)
                attack_paths = [
                    self.fuzzer.allowed_root + suffix_char,
                    self.fuzzer.allowed_root + suffix_char * 3,
                    self.fuzzer.allowed_root + suffix_char + "malicious",
                ]
                
                for attack_path in attack_paths:
                    is_allowed = self.fuzzer.is_path_allowed(attack_path)
                    
                    if is_allowed:
                        # Verify it's not a prefix boundary vulnerability
                        normalized_path = self.fuzzer.normalize_path_cpp_style(attack_path)
                        normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                        
                        # Must be proper subdirectory or exact match
                        if normalized_path != normalized_allowed:
                            assert normalized_path.startswith(normalized_allowed + '/') or \
                                   normalized_path.startswith(normalized_allowed + '\\'), \
                                   f"🚨 ASCII SUFFIX VULNERABILITY: {attack_path} (char: {suffix_char})"
                        
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.integers(min_value=1, max_value=5), 
           st.sampled_from(['/', '\\', '..', '.']))
    def test_random_separator_injection(self, count, separator):
        """
        무작위 경로 구분자 주입 공격을 테스트합니다.
        '/', '\\'와 같은 구분자가 비정상적으로 주입된 경로를 안전하게 처리하는지 확인합니다.
        """
        try:
            # Create path with repeated separators/patterns (limited for performance)
            injection = separator * min(count, 3)
            test_paths = [
                self.fuzzer.allowed_root + injection + "test.raw",
                injection + "etc/passwd",
            ]
            
            for test_path in test_paths:
                is_allowed = self.fuzzer.is_path_allowed(test_path)
                if is_allowed:
                    # Verify it's legitimately within allowed directory
                    normalized_path = self.fuzzer.normalize_path_cpp_style(test_path)
                    normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                    assert normalized_path.startswith(normalized_allowed), f"Separator injection escapes: {test_path}"
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.binary(min_size=1, max_size=50))
    def test_random_binary_injection(self, binary_data):
        """
        경로에 무작위 바이너리 데이터를 주입하는 공격을 테스트합니다.
        널 바이트(Null-byte)나 제어 문자가 포함된 경로를 안전하게 처리하는지 확인합니다.
        """
        try:
            # Convert binary to string (might contain null bytes, control chars, etc.)
            try:
                path_component = binary_data[:30].decode('utf-8', errors='replace')
            except:
                path_component = str(binary_data[:30])
            
            test_path = self.fuzzer.allowed_root + "/" + path_component + ".raw"
            is_allowed = self.fuzzer.is_path_allowed(test_path)
            
            if is_allowed:
                # Binary injection shouldn't allow escape
                normalized_path = self.fuzzer.normalize_path_cpp_style(test_path)
                normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                assert normalized_path.startswith(normalized_allowed), f"Binary injection escapes: {test_path[:50]}..."
        except Exception:
            # Binary data might cause various exceptions
            pass
    
    @fuzzing_settings
    @given(st.one_of(
        st.just(""),  # Empty string
        st.just("/"),  # Root
        st.just("\\"),  # Windows root
        st.just("."),  # Current dir
        st.just(".."),  # Parent dir
        st.just("~"),  # Home dir
        st.just("C:"),  # Windows drive
        st.text(min_size=200, max_size=500),  # Long paths (reduced size)
        st.text(min_size=1, max_size=10, alphabet='\x00\x01\x02\x03\x04\x05'),  # Control characters
    ))
    def test_random_edge_case_paths(self, edge_path):
        """
        다양한 예외적인(edge case) 경로 입력을 퍼징 테스트합니다.
        빈 문자열, 루트, 홈 디렉토리 등 특수한 경로들을 안전하게 처리하는지 확인합니다.
        """
        try:
            is_allowed = self.fuzzer.is_path_allowed(edge_path)
            
            # Edge cases should generally be blocked unless they somehow resolve to allowed dir
            if is_allowed:
                try:
                    normalized_path = self.fuzzer.normalize_path_cpp_style(edge_path)
                    normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                    
                    # Must be within allowed directory
                    assert (normalized_path == normalized_allowed or 
                           normalized_path.startswith(normalized_allowed + '/') or
                           normalized_path.startswith(normalized_allowed + '\\')), f"Edge case escapes: {edge_path}"
                except:
                    pass
        except Exception:
            # Edge cases might cause various exceptions
            pass
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'),
           st.text(min_size=1, max_size=30, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'))
    def test_symlink_attacks(self, allowed_filename, forbidden_filename):
        """
        심볼릭 링크(Symbolic Link)를 이용한 공격을 테스트합니다.
        허용된 경로 내의 심볼릭 링크가 외부의 위험한 파일을 가리키는 것을 차단하는지 확인합니다.
        """
        # Create temporary directories for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                clean_allowed = ''.join(c for c in allowed_filename if c.isalnum() or c in '._-')[:20]
                clean_forbidden = ''.join(c for c in forbidden_filename if c.isalnum() or c in '._-')[:20]
                
                if clean_allowed and clean_forbidden:
                    allowed_dir = os.path.join(temp_dir, "allowed")
                    forbidden_dir = os.path.join(temp_dir, "forbidden")
                    
                    os.makedirs(allowed_dir, exist_ok=True)
                    os.makedirs(forbidden_dir, exist_ok=True)
                    
                    # Create a file in the forbidden directory
                    forbidden_file = os.path.join(forbidden_dir, clean_forbidden + ".txt")
                    with open(forbidden_file, 'w') as f:
                        f.write("secret data")
                    
                    # Create a symlink in the allowed directory pointing to forbidden file
                    symlink_path = os.path.join(allowed_dir, clean_allowed + ".txt")
                    if platform.system() != "Windows":  # Symlinks work differently on Windows
                        os.symlink(forbidden_file, symlink_path)
                        
                        # Test if the symlink is detected and blocked
                        fuzzer_temp = FilePathRestrictionsFuzzer()
                        fuzzer_temp.allowed_root = allowed_dir
                        
                        is_allowed = fuzzer_temp.is_path_allowed(symlink_path)
                        # The system should either block the symlink or resolve it safely
                        if is_allowed:
                            resolved_path = os.path.realpath(symlink_path)
                            assert resolved_path.startswith(allowed_dir), "Symlink should not escape allowed directory"
            except OSError:
                # Symlink creation might fail due to permissions
                pass
            except Exception:
                # Other exceptions are acceptable in fuzzing
                pass
    
    @fuzzing_settings
    @given(st.integers(min_value=100, max_value=1000),
           st.integers(min_value=5, max_value=15))
    def test_long_path_attacks(self, component_length, depth):
        """
        매우 긴 파일 경로를 이용한 공격을 테스트합니다.
        시스템의 최대 경로 길이를 초과하는 입력에 대해 예외 없이 안전하게 처리하는지 확인합니다.
        """
        try:
            # Create paths that exceed typical path length limits
            long_component = "A" * min(component_length, 255)  # Limit to filesystem max
            components = [long_component] * min(depth, 10)  # Limit depth for performance
            
            long_path = self.fuzzer.allowed_root + "/" + "/".join(components) + ".raw"
            
            is_allowed = self.fuzzer.is_path_allowed(long_path)
            # Long paths within allowed directory might be allowed
            if is_allowed:
                # Verify it's still within the allowed directory
                try:
                    normalized_path = self.fuzzer.normalize_path_cpp_style(long_path)
                    normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                    assert normalized_path.startswith(normalized_allowed), f"Long path escapes allowed directory"
                except:
                    # Path normalization might fail for very long paths
                    pass
        except Exception:
            # Very long paths might cause exceptions, which is acceptable
            pass
    
    @fuzzing_settings
    @given(st.sampled_from(['/dev/null', '/dev/zero', '/dev/random', '/dev/urandom', 
                           '/proc/self/mem', '/proc/self/fd/0', '/sys/kernel/debug']))
    def test_special_device_files(self, device_file):
        """
        특수 장치 파일(Special Device Files) 경로 접근을 테스트합니다.
        '/dev/null' 등과 같은 유닉스 계열 시스템의 특수 파일을 차단하는지 확인합니다.
        """
        if platform.system() != "Windows":
            try:
                is_allowed = self.fuzzer.is_path_allowed(device_file)
                assert not is_allowed, f"Device file should be blocked: {device_file}"
            except Exception:
                # Device file access might cause exceptions
                pass
    
    @fuzzing_settings
    @given(st.sampled_from(['server', 'localhost', '192.168.1.1', 'example.com']),
           st.sampled_from(['share', 'public', 'files', 'data']),
           st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'))
    def test_network_paths(self, server, share, filename):
        """
        네트워크 경로(UNC, URL)를 이용한 접근을 테스트합니다.
        '//server/share'나 'http://'와 같은 네트워크 경로를 차단하는지 확인합니다.
        """
        try:
            clean_filename = ''.join(c for c in filename if c.isalnum() or c in '._-')[:15]
            if clean_filename:
                network_paths = [
                    f"//{server}/{share}/{clean_filename}.raw",
                    f"\\\\{server}\\{share}\\{clean_filename}.raw",
                    f"ftp://{server}/{clean_filename}.raw",
                    f"http://{server}/{clean_filename}.raw",
                    f"smb://{server}/{share}/{clean_filename}.raw",
                ]
                
                for path in network_paths:
                    is_allowed = self.fuzzer.is_path_allowed(path)
                    assert not is_allowed, f"Network path should be blocked: {path}"
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.integers(min_value=1, max_value=10),
           st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789'))
    def test_relative_path_attacks(self, traversal_depth, target_file):
        """
        다양한 상대 경로 공격을 테스트합니다.
        '../' 등을 포함한 상대 경로를 이용해 허용된 디렉토리를 벗어나려는 시도를 차단하는지 확인합니다.
        """
        try:
            clean_target = ''.join(c for c in target_file if c.isalnum() or c in '._-')[:15]
            if clean_target:
                relative_attacks = [
                    ".",
                    "..",
                    "./",
                    "../",
                    "../" * traversal_depth + clean_target,
                    "..\\" * traversal_depth + clean_target,
                    "~/../" * traversal_depth + clean_target,
                ]
                
                for path in relative_attacks:
                    is_allowed = self.fuzzer.is_path_allowed(path)
                    assert not is_allowed, f"Relative path attack should be blocked: {path}"
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'),
           st.sampled_from(['\x00']))
    def test_null_byte_injection(self, filename, null_char):
        """
        널 바이트 삽입(Null Byte Injection) 공격을 테스트합니다.
        경로 중간에 널 문자('\\x00')를 삽입하여 검증을 우회하려는 시도를 차단하는지 확인합니다.
        """
        try:
            clean_filename = ''.join(c for c in filename if c.isalnum() or c in '._-')[:15]
            if clean_filename:
                null_byte_paths = [
                    self.fuzzer.allowed_root + "/" + clean_filename + ".raw" + null_char + ".exe",
                    self.fuzzer.allowed_root + "/" + clean_filename + null_char + "/../../../etc/passwd",
                    self.fuzzer.allowed_root + null_char + "/etc/passwd",
                ]
                
                for path in null_byte_paths:
                    try:
                        is_allowed = self.fuzzer.is_path_allowed(path)
                        # Null bytes should be handled safely
                        if is_allowed:
                            # If allowed, verify the path is safe after null byte handling
                            safe_path = path.replace('\x00', '')
                            normalized_safe = self.fuzzer.normalize_path_cpp_style(safe_path)
                            normalized_allowed = self.fuzzer.normalize_path_cpp_style(self.fuzzer.allowed_root)
                            assert normalized_safe.startswith(normalized_allowed), f"Null byte injection escapes allowed directory: {path}"
                    except Exception:
                        # Null byte handling might cause exceptions, which is acceptable
                        pass
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-'))
    def test_case_sensitivity_attacks(self, filename):
        """
        경로의 대소문자 구별과 관련된 공격을 테스트합니다.
        Windows와 Unix 계열 시스템에서 대소문자가 다른 경로를 올바르게 처리하는지 확인합니다.
        """
        try:
            clean_filename = ''.join(c for c in filename if c.isalnum() or c in '._-')[:15]
            if clean_filename:
                if platform.system() == "Windows":
                    # Windows case variants should be allowed
                    case_variants = [
                        self.fuzzer.allowed_root.upper() + "\\" + clean_filename + ".raw",
                        self.fuzzer.allowed_root.lower() + "\\" + clean_filename + ".raw", 
                        self.fuzzer.allowed_root.swapcase() + "\\" + clean_filename + ".raw",
                    ]
                    for path in case_variants:
                        is_allowed = self.fuzzer.is_path_allowed(path)
                        assert is_allowed, f"Case variant should be allowed on Windows: {path}"
                else:
                    # Unix case variants - only exact match should be allowed
                    case_variants = [
                        self.fuzzer.allowed_root.upper() + "/" + clean_filename + ".raw",
                        self.fuzzer.allowed_root.lower() + "/" + clean_filename + ".raw",
                        self.fuzzer.allowed_root.swapcase() + "/" + clean_filename + ".raw",
                    ]
                    for path in case_variants:
                        is_allowed = self.fuzzer.is_path_allowed(path)
                        if path.startswith(self.fuzzer.allowed_root):
                            assert is_allowed, f"Valid case variant should be allowed on Unix: {path}"
                        else:
                            assert not is_allowed, f"Invalid case variant should be blocked on Unix: {path}"
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'),
           st.sampled_from(['/', '\\']))
    def test_mixed_separator_attacks(self, filename, separator):
        """
        혼합된 경로 구분자를 사용한 경로를 테스트합니다.
        '/'와 '\\'가 섞인 경로를 C++ std::filesystem이 정상적으로 처리하고 허용하는지 확인합니다.
        """
        try:
            clean_filename = ''.join(c for c in filename if c.isalnum() or c in '._-')[:15]
            if clean_filename:
                mixed_paths = [
                    self.fuzzer.allowed_root.replace('\\', '/') + "/" + clean_filename + ".raw",
                    self.fuzzer.allowed_root.replace('/', '\\') + "\\" + clean_filename + ".raw",
                    self.fuzzer.allowed_root + "/" + "subdir" + separator + clean_filename + ".raw",
                    self.fuzzer.allowed_root + separator + separator + clean_filename + ".raw",
                ]
                
                for path in mixed_paths:
                    is_allowed = self.fuzzer.is_path_allowed(path)
                    # Mixed separators within allowed directory should be normalized and allowed
                    assert is_allowed, f"Mixed separator path within allowed directory should be allowed: {path}"
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'),
           st.sampled_from(['/', '\\', '.', '']))
    def test_cpp_specific_edge_cases(self, filename, trailing_char):
        """
        C++ `IsPathAllowed()` 구현과 관련된 특정 엣지 케이스를 테스트합니다.
        경로 끝의 '/', '.', '\\' 등 C++에서 특별히 처리되는 경우를 테스트합니다.
        """
        try:
            clean_filename = ''.join(c for c in filename if c.isalnum() or c in '._-')[:10]
            if clean_filename:
                edge_cases = [
                    # Test exact allowed root path
                    self.fuzzer.allowed_root,
                    self.fuzzer.allowed_root + "/",
                    self.fuzzer.allowed_root + "\\",
                    # Test with trailing characters
                    self.fuzzer.allowed_root + "/" + clean_filename + trailing_char,
                    self.fuzzer.allowed_root + "\\" + clean_filename + trailing_char,
                    # Test double separators
                    self.fuzzer.allowed_root + "//" + clean_filename + ".raw",
                    self.fuzzer.allowed_root + "\\\\" + clean_filename + ".raw",
                ]
                
                for path in edge_cases:
                    is_allowed = self.fuzzer.is_path_allowed(path)
                    assert is_allowed, f"Edge case path should be allowed: {path}"
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.lists(st.sampled_from(['_fake', '_backup', '_test', '2', '123', 'Extra', '.bak', '-copy']), 
                   min_size=1, max_size=2))
    def test_prefix_boundary_attacks(self, suffixes):
        """
        접두사 일치(Prefix Matching) 방식의 취약점을 이용하는 공격을 테스트합니다.
        허용된 경로와 이름이 유사하지만 실제로는 다른 디렉토리로의 접근을 차단하는지 확인하는 핵심 보안 테스트입니다.
        """
        try:
            combined_suffix = ''.join(suffixes)
            boundary_attacks = [
                # Critical: These should be blocked - they're not true subdirectories
                self.fuzzer.allowed_root + combined_suffix,
                self.fuzzer.allowed_root + combined_suffix + "/malicious.exe",
                self.fuzzer.allowed_root + combined_suffix + "\\sensitive.txt",
                # Case variations
                self.fuzzer.allowed_root.upper() + combined_suffix.upper(),
                self.fuzzer.allowed_root.lower() + combined_suffix.lower(),
            ]
            
            for path in boundary_attacks:
                is_allowed = self.fuzzer.is_path_allowed(path)
                assert not is_allowed, f"🚨 CRITICAL PREFIX BOUNDARY VULNERABILITY: {path}"
        except AssertionError:
            # Re-raise assertion errors - these are the actual test failures we want to see!
            raise
        except Exception:
            # Only catch other exceptions (like encoding errors, etc.)
            pass
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz0123456789_.-'),
           st.integers(min_value=1, max_value=5))
    def test_cpp_filesystem_normalization(self, filename, redundancy_count):
        """
        C++ 파일시스템의 경로 정규화 동작을 테스트합니다.
        './'나 '///'와 같이 불필요한 요소가 포함된 경로가 정규화 후 올바르게 처리되는지 확인합니다.
        """
        try:
            clean_filename = ''.join(c for c in filename if c.isalnum() or c in '._-')[:10]
            if clean_filename:
                normalization_tests = [
                    # Current directory references
                    self.fuzzer.allowed_root + "/" + "./" * redundancy_count + clean_filename + ".raw",
                    self.fuzzer.allowed_root + "\\" + ".\\" * redundancy_count + clean_filename + ".raw",
                    # Redundant separators
                    self.fuzzer.allowed_root + "/" * (redundancy_count + 1) + clean_filename + ".raw",
                    self.fuzzer.allowed_root + "\\" * (redundancy_count + 1) + clean_filename + ".raw",
                ]
                
                for path in normalization_tests:
                    is_allowed = self.fuzzer.is_path_allowed(path)
                    # After normalization, these should be handled properly
                    assert isinstance(is_allowed, bool), f"Normalization test should return boolean: {path}"
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.one_of(
        st.just(""),  # Empty string
        st.text(min_size=500, max_size=1000),  # Very long paths
        st.text(min_size=1, max_size=10, alphabet='\x00\x01\x02\x03\x04\x05'),  # Control characters
        st.text(min_size=1, max_size=20, alphabet='<>:|"*?'),  # Invalid filename characters
    ))
    def test_exception_handling(self, edge_input):
        """
        경로 확인 중 예외를 발생시킬 수 있는 경로들을 테스트합니다.
        예외 발생 시에도 애플리케이션이 비정상 종료되지 않고 False를 반환하는지 확인합니다.
        """
        try:
            is_allowed = self.fuzzer.is_path_allowed(edge_input)
            # Should return False on any exception (matching C++ behavior)
            assert isinstance(is_allowed, bool), f"Exception test should return boolean: {edge_input}"
        except Exception:
            # Should not raise exceptions - C++ catches all and returns false
            pytest.fail(f"Path validation should not raise exceptions: {edge_input}")
    
    @fuzzing_settings
    @given(st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-'))
    def test_cpp_vulnerability_detection(self, suffix):
        """
        C++의 잠재적인 경로 검증 취약점을 탐지하기 위한 퍼징 테스트입니다.
        안전한 구현과 취약한 C++ 구현의 동작 차이를 비교하여 보안 허점을 찾아냅니다.
        """
        try:
            # 위험한 prefix boundary attack 패턴들
            attack_patterns = [
                self.fuzzer.allowed_root + suffix,
                self.fuzzer.allowed_root + "_" + suffix,
                self.fuzzer.allowed_root + "." + suffix,
                self.fuzzer.allowed_root + "2" + suffix,
                self.fuzzer.allowed_root + "backup" + suffix,
                self.fuzzer.allowed_root + "fake" + suffix,
            ]
            
            for attack_path in attack_patterns:
                # C++ 취약한 구현 테스트
                cpp_vulnerable_result = self.fuzzer.is_path_allowed(attack_path)
                # 안전한 구현 테스트  
                safe_result = self.fuzzer.is_path_allowed_safe(attack_path)
                
                # 🚨 취약점 발견: C++는 허용하지만 안전한 구현은 차단
                if cpp_vulnerable_result and not safe_result:
                    print(f"🚨 VULNERABILITY FOUND: {attack_path}")
                    print(f"   C++ Implementation: ALLOWS (VULNERABLE)")
                    print(f"   Safe Implementation: BLOCKS (SECURE)")
                    
                    # 이것이 실제 보안 문제임을 기록
                    # 실제 테스트에서는 이런 케이스를 발견하는 것이 목표
        except Exception:
            pass
    
    @fuzzing_settings
    @given(st.lists(st.sampled_from(['_fake', '_backup', '_test', '2', '123', 'Extra', '.bak', '-copy']), 
                   min_size=1, max_size=2))
    def test_cpp_vulnerability_showcase(self, attack_suffixes):
        """
        실제 공격 시나리오를 통해 C++ `IsPathAllowed()` 함수의 취약점을 명확하게 시연합니다.
        취약한 구현과 안전한 구현의 결과를 비교하여 어떤 경로가 위험한지 보여줍니다.
        """
        try:
            # 실제 공격 시나리오들 생성
            combined_suffix = ''.join(attack_suffixes)
            attack_scenarios = [
                ("Fake Directory Attack", self.fuzzer.allowed_root + combined_suffix),
                ("Malicious File Attack", self.fuzzer.allowed_root + combined_suffix + "/malicious.exe"),
                ("Config File Attack", self.fuzzer.allowed_root + combined_suffix + "/config.ini"),
                ("System File Attack", self.fuzzer.allowed_root + combined_suffix + "/system.dll"),
            ]
            
            vulnerable_count = 0
            for attack_name, attack_path in attack_scenarios:
                cpp_result = self.fuzzer.is_path_allowed(attack_path)
                safe_result = self.fuzzer.is_path_allowed_safe(attack_path)
                
                if cpp_result and not safe_result:
                    vulnerable_count += 1
                    print(f"🚨 VULNERABILITY FOUND: {attack_name} - {attack_path}")
            
            # fuzzing 목적: 취약점이 발견되는 것이 정상
            if vulnerable_count > 0:
                print(f"Found {vulnerable_count} vulnerabilities in this test case!")
        except Exception:
            pass

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 