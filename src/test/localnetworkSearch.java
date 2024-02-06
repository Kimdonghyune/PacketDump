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

public class localnetworkSearch extends Thread{
    //16진수를 아스키코드로 변환
	private static String hexToAscii(String hexString) {
		StringBuilder output = new StringBuilder();
		//16진수로 만들기 위해 2개씩 문자열 분할하여 해당 문자로 아스키 변환
		for(int i = 0; i < hexString.length(); i += 2) {
			String hexValue = hexString.substring(i, i + 2);
			int decimalValue = Integer.parseInt(hexValue, 16);
			output.append((char) decimalValue);
		}
		return output.toString();
	}
	
	@Override
	public void run() {
		//네트워크 장비를 저장하는 공간을 할당
    	ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
    	//오류 메세지를 담는 버퍼
    	StringBuilder errbuf = new StringBuilder();
    	
    	int searchPort = 25;
    	
    	//네트워크 장비를 찾아서 저장, 네트워크 장비를 못찾으면 return하여 종료
    	Pcap.findAllDevs(allDevs, errbuf);
    	if(allDevs.isEmpty()) {
    		System.out.println("네트워크 장치를 찾을 수 없습니다. 오류 : " + errbuf.toString());
    		return;
    	}
    	System.out.println("[ 네트워크 장비 탐색 성공 ]");
    	
    	//찾은 장비를 하나씩 돌면서 정보 출력
    	for(int i = 0; i<allDevs.size(); i++) {
    		PcapIf device = allDevs.get(i);
    		String description = (device.getDescription() != null) ? device.getDescription() : "장비에 대한 설명이 없습니다.";
    		System.out.printf("[%d번] : %s [%s]\n", i, device.getName(), description);
    	}
    	
    	//네트워크 장치 중에서 하나를 선택 (0번 선택 : 로컬 네트워크 장치)
    	PcapIf device = allDevs.get(0);
    	System.out.printf("선택된 장치 %s \n", (device.getDescription() != null) ? device.getDescription() : device.getName());
    	
    	//65536바이트 만큼 패킷 캡처
    	int snaplen = 64 * 1024;
    	
    	//프라미스쿠어스 모드로 설정 - 해당 네트워크 장치로 들어오는 모든 패킷 캡처하는 모드
    	int flags = Pcap.MODE_NON_PROMISCUOUS;
    	
    	//타임 아웃을 20초로 설정
    	int timeout = 20 * 1000;
    	
    	//장치의 패킷 캡처를 활성화합니다 Pcap.openLive(로컬 네트워크 장치, 65536바이트, 프라미스쿠어스 모드, 타임아웃, 에러 정보);
    	Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
    	
    	//Pcap 객체가 생성되지 않으면 오류 메세지 발생
    	if(pcap == null) {
    		System.out.println("패킷 캡처를 위해 네트워크 장치를 여는데 실패 오류: " + errbuf.toString());
    		return;
    	}
    	
    	//IP 주소 객체 생성
    	Ip4 ip = new Ip4();
    	
    	//TCP 주소 객체 생성
    	Tcp tcp = new Tcp();
    	
    	//캡처한 패킷의 헤더 객체 생성
    	PcapHeader header = new PcapHeader(JMemory.POINTER);
    	
    	//패킷 관련 버퍼 생성
    	JBuffer buf = new JBuffer(JMemory.POINTER);
    	
    	//PCAP의 데이터 링크 타입을 JnetPcap의 프로토콜 ID값으로 매핑
    	int id = JRegistry.mapDLTToId(pcap.datalink());
    	
    	//시간 정보 문자열 형식 지정
    	SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    	
    	String filePath = "C:\\data\\Local_Packet_Dump.txt";
        File file = new File(filePath); //File객체 생성
        if(!file.exists()){ //파일이 존재하지 않으면
            try {
				file.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} //신규생성
        }

        // BufferedWriter 생성
        BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(file, false));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
        StringBuffer result = new StringBuffer();
        
    	System.out.println("스캔 시작");
    	//오류가 발생하지 않는 한 계속해서 다음 패킷을 입력받음
    	while(pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) {
    		PcapPacket packet = new PcapPacket(header, buf);
    		packet.scan(id);
    		
    		if(packet.hasHeader(tcp)) {
    			byte[] compare_payloadData = tcp.getPayload();//TCP에 있는 payload 값 가져옴(바이트 형태)
    			String compare_payload = DatatypeConverter.printHexBinary(compare_payloadData);//바이트형태를 문자열형식으로 변환
    			String asciiCode = hexToAscii(compare_payload);//16진수를 아스키 코드로 변환
    			
        		if((tcp.source() == searchPort || tcp.destination() == searchPort) && asciiCode.length() != 0) {
        			Date date = new Date(packet.getCaptureHeader().timestampInMillis());
        			String nowTime1 = sdf1.format(date);
        			System.out.println("시간: " + nowTime1);
        			result.append("=============\n");
        			result.append("시간 : " + nowTime1 + "\n");
        			
        			//출발 포트가 searchPort이면 Jmeter에서 SMEX로
        			if(tcp.source() == searchPort) {
        				System.out.println("Jmeter -> SMEX");
        				result.append("Jmeter -> SMEX\n");
        			}
        			
        			//도착 포트가 searchPort이면 SMEX에서 Jmeter로
        			if(tcp.destination() == searchPort) {
        				System.out.println("SMEX -> Jmeter");
        				result.append("SMEX -> Jmeter\n");
        			}
        			
        			//출발지와 도착지 포트번호 기록
        			System.out.println("출발지 Port 번호 : " + tcp.source());
        			System.out.println("도착지 Port 번호 : " + tcp.destination());
    				result.append("출발지 port 번호 : " + tcp.source() + "\n");
    				result.append("도착지 port 번호 : " + tcp.destination() + "\n");
        			
        			//패킷의 헤더에서 IP 부분만 추출(로컬 네트워크라 둘 다 똑같은 10.10.10.84로 찍힘)
        			if(packet.hasHeader(ip)) {
        				System.out.printf("출발지 IP 주소 : %s\n도착지 IP 주소 : %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));	
        				result.append("출발지 IP 주소 : " + FormatUtils.ip(ip.source()) + "\n");
        				result.append("도착지 IP 주소 : " + FormatUtils.ip(ip.destination()) + "\n");
        			}
        			
        			//packet.hasHeader(payload); <- 해당 패킷에 지정된 헤더정보에 payload가 있는지 여부 판단하는 메소드이며 있으면 payload에 해당 헤더정보 삽입(payload는 헤더정보가 아니라 안찍힘)
        			
        			byte[] tcp_payloadData = tcp.getPayload();//TCP 패킷에서의 payload를 가져옴(16진수 형태)
        			String payloadData = DatatypeConverter.printHexBinary(tcp_payloadData);//16진수형태를 하나의 문자열로 변환
        			String asciiString = hexToAscii(payloadData);//해당 문자열을 아스키 코드로 변환시켜주는 메소드 hexToAscii()
        			System.out.println("데이터 : " + asciiString);
        			if(tcp.getPayload() != null) {
        				result.append("데이터 : " + asciiString + "\n");
        			}
        			
                	try {
						writer.write(result.toString());
						writer.flush();//버퍼의 남은 데이터를 모두 파일로 보냄
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}//result에 저장되어 있는 문자 버퍼에 쓰기
                    
                    result.delete(0, result.length());//result에 저장되어 있는 모든 문자열 제거
        		}
    		}
    	}
    	pcap.close();//패킷 캡처 종료
    	System.out.println("로컬 스캔 종료");
    	
    	//패킷들을 캡처한 정보들을 쓰기
    	try {
			writer.write(result.toString());
	        writer.flush(); //버퍼의 남은 데이터를 모두 쓰기
	        writer.close(); //스트림 종료
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
