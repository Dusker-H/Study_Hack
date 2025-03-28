from PIL import Image
import sys

if len(sys.argv) != 3:
    print(f"사용법: python {sys.argv[0]} <input.png> <output.raw>")
    sys.exit(1)

input_png = sys.argv[1]   # 입력 PNG 파일
output_raw = sys.argv[2]  # 출력 RAW 파일

# PNG 파일 열기 및 변환 (8비트 Grayscale)
img = Image.open(input_png).convert("L")  # "L" 모드: 1픽셀 = 1바이트 (8비트)

# 이미지 데이터를 바이너리로 변환
raw_data = img.tobytes()

# RAW 파일로 저장
with open(output_raw, "wb") as f:
    f.write(raw_data)

print(f"변환 완료: {output_raw}")
