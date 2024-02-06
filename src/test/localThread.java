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

public class localThread extends Thread {
	
	// 16진수를 아스키코드로 변환
	private String hexToAscii(String hexString) {
		StringBuilder output = new StringBuilder();
		// 16진수로 만들기 위해 2개씩 문자열 분할하여 해당 문자로 아스키 변환
		for (int i = 0; i < hexString.length(); i += 2) {
			String hexValue = hexString.substring(i, i + 2);
			int decimalValue = Integer.parseInt(hexValue, 16);
			output.append((char) decimalValue);
		}
		return output.toString();
	}

	public void run() {
		// 네트워크 장비를 저장하는 공간을 할당
		ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
		// 오류 메세지를 담는 버퍼
		StringBuilder errbuf = new StringBuilder();

		int searchPort = 25; //포트 번호 25번으로 설정(필터설정)

		// 네트워크 장비를 찾아서 저장, 네트워크 장비를 못찾으면 return하여 종료
		Pcap.findAllDevs(allDevs, errbuf);
		if (allDevs.isEmpty()) {
			System.out.println("네트워크 장치를 찾을 수 없습니다. 오류 : " + errbuf.toString());
			return;
		}
		System.out.println("[ 네트워크 장비 탐색 성공 ]");

		// 찾은 장비를 하나씩 돌면서 정보 출력
		for (int i = 0; i < allDevs.size(); i++) {
			PcapIf device = allDevs.get(i);
			String description = (device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
			System.out.printf("[%d번] : %s [%s]\n", i, device.getName(), description);
		}

		// 네트워크 장치 중에서 하나를 선택 (0번 선택 : 로컬 네트워크 장치)
		PcapIf device = allDevs.get(0);
		System.out.printf("선택된 장치 %s \n",
				(device.getDescription() != null) ? device.getDescription() : device.getName());

		// 65536바이트 만큼 패킷 캡처
		int snaplen = 64 * 1024;

		// 프라미스쿠어스 모드로 설정 - 해당 네트워크 장치로 들어오는 모든 패킷 캡처하는 모드
		int flags = Pcap.MODE_PROMISCUOUS;

		// 타임 아웃을 20초로 설정 (패킷이 20초동안 들어오지 않는다면 강제 종료 )
		int timeout = 20 * 1000;

		// 장치의 패킷 캡처를 활성화합니다 Pcap.openLive(로컬 네트워크 장치, 65536바이트, 프라미스쿠어스 모드, 타임아웃, 에러 정보);
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

		// 시간 정보 문자열 형식 지정
		SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

		String filePath = "C:\\data\\Local_AllPacket_Dump.txt";// 해당 파일 위치에 텍스트 파일 생성
		File file = new File(filePath); // File 객체 생성
		if (!file.exists()) { // 파일이 존재하지 않으면 파일 생성
			try {
				file.createNewFile();
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
		
		System.out.println(searchPort + "포트 로컬 스캔 시작");
		
		// 데이터를 보내는 위치를 구분짓기 위해 2개의 결과로 나눔
		StringBuffer sourceResult = new StringBuffer(); // sourceResult는 데이터를 보낼때 해당 데이터 내용
		StringBuffer destinationResult = new StringBuffer(); // destinationResult는 데이터를 받을때 해당 데이터의 내용

		// 오류가 발생하지 않는 한 계속해서 다음 패킷을 입력받음
		while ( pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) {
			PcapPacket packet = new PcapPacket(header, buf); // 가져온 패킷 헤더와 데이터로 packet 객체 생성
			packet.scan(id); // scan 메서드는 패킷의 내부 데이터를 읽고 분석하여 프로토콜의 특정 필드나 특징을 식별.

			if (packet.hasHeader(tcp)) {
				if (tcp.source() == searchPort || tcp.destination() == searchPort) {
					Date date = new Date(packet.getCaptureHeader().timestampInMillis()); // 패킷의 시간 정보를 초단위로 가져옴
					String nowTime = sdf1.format(date); // 초 단위를 날짜 형식에 맞춰 문자열로 변환

					byte[] tcp_payloadData = tcp.getPayload();// TCP 패킷에서의 payload를 가져옴 (바이트 형태)
					String payloadData = DatatypeConverter.printHexBinary(tcp_payloadData);// 16진수형태를 하나의 문자열로 변환
					String asciiString = hexToAscii(payloadData);// 해당 문자열을 아스키 코드로 변환시켜주는 메소드 hexToAscii()

					packet.hasHeader(ip);

					// 출발 포트가 searchPort이면 Jmeter에서 SMEX로 화살표 표시(Jmeter가 searchPort이기 때문)
					if (tcp.source() == searchPort) {
						if (sourceResult.length() == 0) {
							sourceResult.append("============ \n" + "시간 : " + nowTime + "\n" + "Jmeter -> SMEX\n"
									+ "출발지 IP 주소 : " + FormatUtils.ip(ip.source()) + "\n" + "도착지 IP 주소 : "
									+ FormatUtils.ip(ip.destination()) + "\n" + "출발지 Port 주소 : " + tcp.source() + "\n"
									+ "도착지 Port 주소 : " + tcp.destination() + "\n" + "데이터 : \n");
						} else {
							sourceResult.append(asciiString);
						}
					}

					// 도착 포트가 searchPort이면 SMEX에서 Jmeter로 화살표 표시(Jmeter가 searchPort이기 때문)
					if (tcp.destination() == searchPort) {
						if (destinationResult.length() == 0) {
							destinationResult.append("============ \n" + "시간 : " + nowTime + "\n" + "SMEX -> Jmeter\n"
									+ "출발지 IP 주소 : " + FormatUtils.ip(ip.source()) + "\n" + "도착지 IP 주소 : "
									+ FormatUtils.ip(ip.destination()) + "\n" + "출발지 Port 주소 : " + tcp.source() + "\n"
									+ "도착지 Port 주소 : " + tcp.destination() + "\n" + "데이터 : \n");
						} else {
							destinationResult.append(asciiString);
						}
					}
				}
			}
		}
		
		if(pcap != null) { // timeout이 되었을때는 이미 pcap이 닫혀 있어서 또 pcap을 닫는 것을 방지
			pcap.close();
		}
		
		System.out.println(searchPort + "포트 로컬 스캔 종료");
		System.out.println(sourceResult.toString());
		System.out.println(destinationResult.toString());
		try {
			writer.write(sourceResult.toString());
			writer.flush();
			writer.write(destinationResult.toString());
			writer.flush();
			writer.close(); 
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
