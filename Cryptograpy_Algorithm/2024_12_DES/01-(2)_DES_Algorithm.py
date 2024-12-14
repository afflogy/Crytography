
INITIAL_PERMUTATION = [58, 50, 42, 34, 26, 18, 10, 2,
                       60, 52, 44, 36, 28, 20, 12, 4,
                       62, 54, 46, 38, 30, 22, 14, 6,
                       64, 56, 48, 40, 32, 24, 16, 8,
                       57, 49, 41, 33, 25, 17, 9, 1,
                       59, 51, 43, 35, 27, 19, 11, 3,
                       61, 53, 45, 37, 29, 21, 13, 5,
                       63, 55, 47, 39, 31, 23, 15, 7]

FINAL_PERMUTATION = [40, 8, 48, 16, 56, 24, 64, 32,
                     39, 7, 47, 15, 55, 23, 63, 31,
                     38, 6, 46, 14, 54, 22, 62, 30,
                     37, 5, 45, 13, 53, 21, 61, 29,
                     36, 4, 44, 12, 52, 20, 60, 28,
                     35, 3, 43, 11, 51, 19, 59, 27,
                     34, 2, 42, 10, 50, 18, 58, 26,
                     33, 1, 41, 9, 49, 17, 57, 25]

EXPANSION_PERMUTATION = [32, 1, 2, 3, 4, 5,
                         4, 5, 6, 7, 8, 9,
                         8, 9, 10, 11, 12, 13,
                         12, 13, 14, 15, 16, 17,
                         16, 17, 18, 19, 20, 21,
                         20, 21, 22, 23, 24, 25,
                         24, 25, 26, 27, 28, 29,
                         28, 29, 30, 31, 32, 1]

S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], 
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8 ,11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 10, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 10, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 10, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 9, 3, 5, 5, 11]]]

STRAIGHT_PERMUTATION = [16, 7, 20, 21, 29, 12, 28, 17,
                        1, 15, 23, 26, 5, 18, 31, 10,
                        2, 8, 24, 14, 32, 27, 3, 9,
                        19, 13, 30, 6, 22, 11, 4, 25]

PARITY_DROP = [57, 49, 41, 33, 25, 17, 9, 1,
                58, 50, 42, 34, 26, 18, 10, 2,
                59, 51, 43, 35, 27, 19, 11, 3,
                60, 52, 44, 36, 63, 55, 47, 39,
                31, 23, 15, 7, 62, 54, 46, 38,
                30, 22, 14, 6, 61, 53, 45, 37,
                29, 21, 13, 5, 28, 20, 12, 4]

SHIFT_N = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

COMPRESSION_PERMUTATION = [14, 17, 11, 24, 1, 5, 3, 28,
                           15, 6, 21, 10, 23, 19, 12, 4,
                           26, 8, 16, 7, 27, 20, 13, 2,
                           41, 52, 31, 37, 47, 55, 30, 40,
                           51, 45, 33, 48, 44, 49, 39, 56,
                           34, 53, 46, 42, 50, 36, 29, 32]

def text_to_64bit_block(text):
    """
    다양한 입력 형식을 64비트 이진 블록으로 변환
    
    입력 형식:
    1. 한국어 텍스트
    2. 영어 텍스트
    3. 10진수 문자열
    4. 16진수 문자열
    
    Args:
        text (str): 변환할 텍스트 또는 숫자 문자열
    
    Returns:
        str:
    """

    def is_korean(s):
        """문자열이 한국어인지 확인"""
        return any('\uAC00' <= char <= '\uD7A3' for char in s)
    
    def is_hex(s):
        """문자열이 16진수인지 확인"""
        return all(c in '0123456789ABCDEFabcdef' for c in s)
    
    def is_decimal(s):
        """문자열이 10진수 숫자인지 확인"""
        try:
            int(s)
            return True
        except ValueError:
            return False
    
    try:
        # 입력 형식 식별
        if is_korean(text):
            # 한국어 텍스트를 UTF-8 16진수로 변환
            hex_text = text.encode('utf-8').hex()
        elif text.isalpha():
            # 영어 텍스트를 UTF-8 16진수로 변환
            hex_text = text.encode('utf-8').hex()
        elif is_hex(text):
            # 이미 16진수인 경우
            hex_text = text
        elif is_decimal(text):
            # 10진수를 16진수로 변환
            hex_text = hex(int(text))[2:]
        else:
            # 기타 다른 형식의 텍스트
            hex_text = text.encode('utf-8').hex()
        
        # 16진수를 64비트로 패딩 또는 자르기
        hex_text = hex_text.zfill(16)[:16]
        # 16진수를 64비트 이진수로 변환
        return bin(int(hex_text, 16))[2:].zfill(64)
    
    except Exception as e:
        raise ValueError(f"입력 변환 중 오류 발생: {e}")

def permute(block, permutation_table):
    """Perform permutation based on the given table"""
    return ''.join(block[p-1] for p in permutation_table)

def expand_block(block):
    return permute(block, EXPANSION_PERMUTATION)

def apply_sbox(block):
    """s-box에서 48비트를 연산"""
    output = ''
    for i in range(8):
        # 6비트씩 8블록 분할할
        segment = block[i*6:(i+1)*6]
        
        # 6비트를 통해 행렬 계산
        row = int(segment[0] + segment[5], 2)
        col = int(segment[1:5], 2)
        
        # s-box에서 값을 도출
        val = S_BOXES[i][row][col]

        # 4비트 값으로 변환
        output += bin(val)[2:].zfill(4)

    return output

def generate_subkeys(key):
    """16개의 서브키 생성"""
    # parity-drop으로 56비트 생성
    reduced_key = permute(key, PARITY_DROP)
    
    # 56비트를 28비트 분할
    left = reduced_key[:28]
    right = reduced_key[28:]
    
    subkeys = []
    for shift in SHIFT_N:
        # 라운드에 맞는 left shift 진행
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]

        # 56비트로 합치고 48비트로 축소 치환
        combined = left + right
        subkey = permute(combined, COMPRESSION_PERMUTATION)
        subkeys.append(subkey)
    
    return subkeys

def f_function(right_block, subkey):
    """F-function(= DES함수)"""
    expanded = expand_block(right_block)
    
    # 서브키와 XOR연산
    xor_result = ''.join(str(int(a) ^ int(b)) for a, b in zip(expanded, subkey))

    # 6x8비트 블록을 S-box에 적용
    sbox_output = apply_sbox(xor_result)
    
    # 최종 s-box 결과를 단순 치환
    return permute(sbox_output, STRAIGHT_PERMUTATION)

def des_encrypt(plaintext, key):
    """DES함수를 사용한 평문 암호화"""
    # 1. 평문과 키값을 이진으로 변환
    plaintext_block = text_to_64bit_block(plaintext)
    key_block = text_to_64bit_block(key)
    
    # 2. 평문 64비트 초기 치환
    permuted_text = permute(plaintext_block, INITIAL_PERMUTATION)
    
    # 3. 각 라운드 별 서브키 생성
    subkeys = generate_subkeys(key_block)
    
    # 4. 64비트를 32비트 블록 L과 R로 분할
    left = permuted_text[:32]
    right = permuted_text[32:]
    
    # 5. Feistal 알고리즘의 16라운드 실행
    for i in range(16):
        # 기존 R32비트 저장
        temp_right = right
        
        # R32비트에 F-function 적용 => 새로운 R32비트
        f_output = f_function(right, subkeys[i])
        
        if i == 15:
            # 마지막 Round에서만 swap 패스
            left = f_output

        else :
            # 새로운 R32비트와 L32비트 XOR 연산
            #right = ''.join(str(int(a) ^ int(b)) for a, b in zip(left, f_output))
            right = ''.join('1' if a != b else '0' for a, b in zip(left, f_output))
        
            # L32비트를 기존 R32로 업데이트
            left = temp_right
        
        #print(f"{i} Round: {left}, {right}")
        #print(f"{i} Round: left[ {hex(int(left,2)).zfill(8)} ], right [ {hex(int(right,2)).zfill(8)} ]")

    # 6. 최종 16라운드가 끝나고 L과 R을 합쳐서 64비트 암호문 생성
    final_block = right + left

    # 7. 최종 치환(초기 치환의 역)을 final_block에 적용
    ciphertext = permute(final_block, FINAL_PERMUTATION)
    
    # 8. 64비트 암호문을 16진수로 변환
    return hex(int(ciphertext, 2))[2:].zfill(16)

def des_decrypt(ciphertext, key):
    """DES함수를 사용한 암호문 복호화"""
    # 1. 암호문과 키값을 이진으로 변환
    ciphertext_block = text_to_64bit_block(ciphertext)
    key_block = text_to_64bit_block(key)
    
    # 2. 64비트 암호문을 초기 치환
    permuted_text = permute(ciphertext_block, INITIAL_PERMUTATION)
    
    # 3. 각 라운드에 적용할 서브키를 생성(but, 암호화와는 역방향으로 복호화 진행)
    subkeys = generate_subkeys(key_block)[::-1]
    
    # 4. 64비트를 32비트 블록 L과 R로 분할
    left = permuted_text[:32]
    right = permuted_text[32:]
    
    # 5. Feistal 알고리즘의 16라운드 실행
    for i in range(16):
        # 기존 R32비트 저장
        temp_right = right
        
        # R32비트에 F-function 적용 => 새로운 R32비트
        f_output = f_function(right, subkeys[i])
        
        if i == 15:
            # 마지막 Round에서만 swap 패스
            left = f_output

        else :
            # 새로운 R32비트와 L32비트 XOR 연산
            right = ''.join('1' if a != b else '0' for a, b in zip(left, f_output))
        
            # L32비트를 기존 R32로 업데이트
            left = temp_right
    
    # 6. 최종 16라운드가 끝나고 L과 R을 합쳐서 64비트 암호문 생성
    final_block = right + left
    
    # 7. 최종 치환(초기 치환의 역)을 final_block에 적용
    plaintext = permute(final_block, FINAL_PERMUTATION)
    
    # 8. 결과 출력
    try:
        hex_text = hex(int(plaintext, 2))[2:]
        byte_text = bytes.fromhex(hex_text)

        try:
            return byte_text.decode('utf-8')
        except UnicodeDecodeError:
            try:
                return byte_text.decode('euc-kr')
            except UnicodeDecodeError:
                # 16진수 문자열로 반환
                return hex_text
    except Exception as e:
        return f"복호화 중 오류 발생: {e}"


def main():

    plaintext = input("Plaintext: ")
    key = input("Key: ")
    
    # Encrypt
    ciphertext = des_encrypt(plaintext, key)
    print("Ciphertext:", ciphertext)
    
    # Decrypt
    decrypted = des_decrypt(ciphertext, key)
    print("Decrypted:", decrypted)

if __name__ == "__main__":
    main()