import io

def decode(raw,enc):
    prev = -1
    while True :
        c = raw.read(1)
        if not c :
            break
        enc.write(c)
        if prev == c :
            while True :
                c = raw.read(1)
                if not c :
                    break
                if c!=prev :
                    change = int.from_bytes(c,byteorder='little')
                    for i in range(change) :
                        print(i)
                        enc.write(prev)
                    break
        else:
            prev = c

def main():
    with open('secretMessage.enc','rb') as raw, open('secretMessage.raw','wb') as enc:
        decode(raw, enc)

if __name__ == '__main__':
    main()