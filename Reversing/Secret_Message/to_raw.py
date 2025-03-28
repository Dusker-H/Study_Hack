from PIL import Image
import sys

if len(sys.argv) != 4:
    print(f"사용법: python {sys.argv[0]} <input.raw> <width> <height>")
    sys.exit(1)

input_raw = sys.argv[1]
width = int(sys.argv[2])
height = int(sys.argv[3])

# RAW 파일 열기
with open(input_raw, "rb") as f:
    raw_data = f.read()

# PNG로 변환 (8비트 Grayscale)
img = Image.frombytes("L", (width, height), raw_data)
img.save("restored.png")

print("PNG 변환 완료: restored.png")
