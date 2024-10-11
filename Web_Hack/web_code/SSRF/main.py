# pip3 install flask requests # 파이썬 flask, requests 라이브러리를 설치하는 명령입니다.
# python3 main.py # 파이썬 코드를 실행하는 명령입니다.

from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/image_downloader")
def image_downloader():
    # 이용자가 입력한 URL에 HTTP 요청을 보내고 응답을 반환하는 페이지 입니다.
    image_url = request.args.get("image_url", "") # URL 파라미터에서 image_url 값을 가져옵니다.
    response = requests.get(image_url) # requests 라이브러리를 사용해서 image_url URL에 HTTP GET 메소드 요청을 보내고 결과를 response에 저장합니다.
    return ( # 아래의 3가지 정보를 반환합니다.
        response.content, # HTTP 응답으로 온 데이터
        200, # HTTP 응답 코드
        {"Content-Type": response.headers.get("Content-Type", "")}, # HTTP 응답으로 온 헤더 중 Content-Type(응답 내용의 타입)
    )


@app.route("/request_info")
def request_info():
    # 접속한 브라우저(User-Agent)의 정보를 출력하는 페이지 입니다.
    return request.user_agent.string
    
    
app.run(host="127.0.0.1", port=8888)

