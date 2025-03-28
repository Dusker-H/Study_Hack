fIn = open("secretMessage.enc", "rb")
fOut = open("secretMessage.raw", "wb")
nowChar = prevChar = None
while True:
    nowChar = fIn.read(1)
    if nowChar == b"":
        break
    fOut.write(nowChar)
    if nowChar == prevChar:
        _count = fIn.read(1)
        if _count == b"":
            break
        count = ord(_count)
        for _ in range(count):
            fOut.write(nowChar)
    prevChar = nowChar
