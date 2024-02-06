# PacketDump
포트번호를 이용하여 이동하는 패킷의 데이터 내용 확인
네트워크 장치는 컴퓨터별로 다르니 확인해서 확인하고자 하는 패킷이 어느 네트워크 장치인지 확인해서 장치 변경 필요
searchPort 값을 변경하여 찾고자 하는 프로세스의 포트 번호를 입력하면 됨
<필수 - jnetpcap.jar 라이브러리 추가, jnetpcap.dll 파일은 system 폴더에 추가>

testThread.java(메인) , localThread.java , networkThread.java 3개는 데이터를 한번에 출력
testPacket(메인), localnetworkSearch.java , networkSearch.java 3개는 데이터를 따로 따로 출력
