package test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class networkThread extends Thread {
	private boolean end;
	// 16진수를 아스키코드로 변환
	private static String hexToAscii(String hexString) {
		StringBuilder output = new StringBuilder();
		// 16진수로 만들기 위해 2개씩 문자열 분할하여 해당 문자로 아스키 변환
		for (int i = 0; i < hexString.length(); i += 2) {
			String hexValue = hexString.substring(i, i + 2);
			int decimalValue = Integer.parseInt(hexValue, 16);
			output.append((char) decimalValue);
		}
		return output.toString();
	}

	@Override
	public void run() {
		end = true;
		try {
			Thread.sleep(2000); //2초간 슬립 네트워크 장비 탐지 중복 방지
		} catch (InterruptedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		// 네트워크 장비를 저장하는 공간을 할당
		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
		// 오류 메세지를 담는 버퍼
		StringBuilder errbuf = new StringBuilder();

		int searchPort = 587; // 포트 번호 587번으로 설정(필터 설정)

		// 네트워크 장비를 찾아서 저장, 네트워크 장비를 못찾으면 return하여 종료
		Pcap.findAllDevs(allDevs, errbuf);
		if (allDevs.isEmpty()) {
			System.out.println("네트워크 장치를 찾을 수 없습니다. 오류 : " + errbuf.toString());
			return;
		}
		System.out.println("[ 네트워크 장비 탐색 성공 ]");

		// 찾은 네트워크 장비를 하나씩 돌면서 정보 출력
		for (int i = 0; i < allDevs.size(); i++) {
			PcapIf device = allDevs.get(i);
			String description = (device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
			System.out.printf("[%d번] : %s [%s]\n", i, device.getName(), description);
		}

		// 네트워크 장치 중에서 하나를 선택 (4번 선택 : 이더넷 네트워크 장치)
		PcapIf device = allDevs.get(4);
		System.out.printf("선택된 장치 %s \n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());

		// 65536바이트 만큼 패킷 캡처
		int snaplen = 64 * 1024;

		// 프라미스쿠어스 모드로 설정 - 해당 네트워크 장치로 들어오는 모든 패킷 캡처하는 모드
		int flags = Pcap.MODE_PROMISCUOUS;

		// 타임 아웃을 20초로 설정 (20초 동안 패킷이 들어오지 않으면 강제 종료)
		int timeout = 20 * 1000;

		// 장치의 패킷 캡처를 활성화합니다 Pcap.openLive(네트워크 장치 이름, 패킷 캡처할 크기, 시간, 에러 정보);
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		// Pcap 객체가 생성되지 않으면 오류 메세지 발생
		if (pcap == null) {
			System.out.println("패킷 캡처를 위해 네트워크 장치를 여는데 실패 오류: " + errbuf.toString());
			return;
		}

		// IP 주소 객체 생성
		Ip4 ip = new Ip4();

		// TCP 주소 객체 생성
		Tcp tcp = new Tcp();

		// 캡처한 패킷의 헤더 객체 생성
		// JMemory.POINTER를 전달하게 되는데 이는 헤더를 메모리의 특정 위치에 할당하는 데 사용되는 JNA(Java Native Access) 라이브러리의 Pointer를 나타냄
		// 패킷 헤더를 메모리의 특정 위치에 할당하여 사용
		PcapHeader header = new PcapHeader(JMemory.POINTER);

		// 패킷 관련 버퍼 생성
		// 패킷 관련 버퍼를 메모리의 특정 위치에 할당하여 사용
		JBuffer buf = new JBuffer(JMemory.POINTER);

		// PCAP의 데이터 링크 타입을 JnetPcap의 프로토콜 ID값으로 매핑
		int id = JRegistry.mapDLTToId(pcap.datalink());

		// 시간 형식 설정
		SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		String filePath = "C:\\data\\network_allPacket_Dump.txt"; // 해당 위치에 해당 파일명으로 파일 생성
		File file = new File(filePath); // File 객체 생성
		if (!file.exists()) { // 파일이 존재하지 않으면
			try {
				file.createNewFile(); // 파일 생성
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		// BufferedWriter 생성
		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(file, false)); // 해당 파일이 있으면 기존 파일 내용 지우고 덮어 쓰기
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// 데이터를 보내는 위치를 구분 짓기 위해 결과를 2개로 나눔
		StringBuffer sourceResult = new StringBuffer(); // sourceResult는 데이터를 보낼때 보낸 데이터 저장
		StringBuffer destinationResult = new StringBuffer(); // destinationResult는 데이터를 받을때 받은 데이터 저장

		System.out.println(searchPort + "포트 네트워크 스캔 시작");
		// 오류가 발생하지 않는 한 계속해서 다음 패킷을 입력받음, end값을 이용하여 무한루프 탈출(네트워크 장치의 경우 다른 인터넷 패킷이 들어와 timeout으로 종료가 안됨)
		while (pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK && end) {
			PcapPacket packet = new PcapPacket(header, buf); //패킷 헤더와 패킷 데이터로 packet 생성
			packet.scan(id); // scan 메서드는 패킷의 내부 데이터를 읽고 분석하여 프로토콜의 특정 필드나 특징을 식별
			// TCP(포트번호)가 587이면 SMTP
			if (packet.hasHeader(tcp)) {
				byte[] compare_payloadData = tcp.getPayload(); // TCP에 있는 payload 값 가져옴(바이트 형태)
				String compare_payload = DatatypeConverter.printHexBinary(compare_payloadData); // 바이트형태를 문자열형식으로 변환
				String asciiCode = hexToAscii(compare_payload); // 16진수를 아스키 코드로 변환

				if ((tcp.source() == searchPort || tcp.destination() == searchPort) && asciiCode.length() != 0) {
					Date date = new Date(packet.getCaptureHeader().timestampInMillis()); // 패킷 헤더에서 시간을 초단위로 가져옴
					String nowTime = sdf1.format(date); // 초 단위를 날짜 형식에 맞춰 문자열로 저장

					// packet.hasHeader(payload) ->이 방식은 packet의 헤더정보에서 payload가 있는지 여부를 확인하는 메소드로
					// 따로 payload가 안잡힘(tcp의 payload에서 가져와야함)

					byte[] tcp_payloadData = tcp.getPayload();// TCP에 있는 payload 값 가져옴(바이트 형태)
					String payloadData = DatatypeConverter.printHexBinary(tcp_payloadData);// 바이트형태를 문자열형식으로 변환
					String asciiString = hexToAscii(payloadData);// 16진수를 아스키 코드로 변환
					
					packet.hasHeader(ip); // 패킷 헤더 정보에서 ip 정보를 가져옴
					if(tcp.source() == searchPort) {
						if(sourceResult.length() == 0) {
							sourceResult.append("============ \n" + "시간 : " + nowTime + "\n" + "SMEX -> SMTP \n"
									+ "출발지 IP 주소 : " + FormatUtils.ip(ip.source()) + "\n" + "도착지 IP 주소 : " + FormatUtils.ip(ip.destination()) + "\n"
									+ "출발지 Port 주소 : " + tcp.source() + "\n" + "도착지 Port 주소 :" + tcp.destination() + "\n" + "데이터 : \n"
									);							
						}
						else {
							sourceResult.append(asciiString); // 데이터 추가
						}
					}
					
					if(tcp.destination() == searchPort) {
						if(destinationResult.length() == 0) {
							destinationResult.append("\n============ \n" + "시간 : " + nowTime + "\n" + "SMEX -> SMTP \n"
									+ "출발지 IP 주소 : " + FormatUtils.ip(ip.source()) + "\n" + "도착지 IP 주소 : " + FormatUtils.ip(ip.destination()) + "\n"
									+ "출발지 Port 주소 : " + tcp.source() + "\n" + "도착지 Port 주소 :" + tcp.destination() + "\n" + "데이터 : \n"
									);							
						}
						else {
							destinationResult.append(asciiString); // 데이터 추가
						}
					}
				}
			}
		}
		
		if(pcap != null) { //timeout이 되었을 때 이미 pacp은 닫히기 때문에 또 닫는것을 방지
			pcap.close();
		}
		
		try {
			writer.write(sourceResult.toString());
			writer.flush();
			writer.write(destinationResult.toString());
			writer.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println(searchPort + "포트 네트워크 스캔 종료");
		System.out.println(sourceResult.toString());
		System.out.println(destinationResult.toString());
	}
	
	void stopThread() {
		end = false;
	}
}
