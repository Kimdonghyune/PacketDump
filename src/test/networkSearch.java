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

public class networkSearch extends Thread{
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
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		//네트워크 장비를 저장하는 공간을 할당
    	ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
    	//오류 메세지를 담는 버퍼
    	StringBuilder errbuf = new StringBuilder();
    	
    	int smtp = 587;
    	
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
    	
    	//네트워크 장치 중에서 하나를 선택 (4번 선택 : 이더넷)
    	PcapIf device = allDevs.get(4);
    	System.out.printf("선택된 장치 %s \n", (device.getDescription() != null) ? device.getDescription() : device.getName());
    	
    	//65536바이트 만큼 패킷 캡처
    	int snaplen = 64 * 1024;
    	
    	//프라미스쿠어스 모드로 설정 - 해당 네트워크 장치로 들어오는 모든 패킷 캡처하는 모드
    	int flags = Pcap.MODE_PROMISCUOUS;
    	
    	//타임 아웃을 30초로 설정
    	int timeout = 30 * 1000;
    	
    	//장치의 패킷 캡처를 활성화합니다
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
    	
    	//시간 형식 설정
    	SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    	
    	String filePath = "C:\\data\\SMTP_Packet_Dump.txt";//해당 위치에 해당 파일명으로 파일 생성
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
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        StringBuffer result = new StringBuffer();
		
        
    	System.out.println("SMTP 포트 "+ smtp + " 스캔 시작");
    	//오류가 발생하지 않는 한 계속해서 다음 패킷을 입력받음
    	while(pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) {
    		PcapPacket packet = new PcapPacket(header, buf);
    		packet.scan(id);
    		// TCP(포트번호)가 587이면 SMTP
    		if(packet.hasHeader(tcp)) {
    			byte[] compare_payloadData = tcp.getPayload();//TCP에 있는 payload 값 가져옴(바이트 형태)
    			String compare_payload = DatatypeConverter.printHexBinary(compare_payloadData);//바이트형태를 문자열형식으로 변환
    			String asciiCode = hexToAscii(compare_payload);//16진수를 아스키 코드로 변환
    			
        		if((tcp.source() == smtp || tcp.destination() == smtp) && asciiCode.length() != 0) {
        			System.out.println("-------------");
        			Date date = new Date(packet.getCaptureHeader().timestampInMillis());
        			String nowTime1 = sdf1.format(date);

        			//패킷의 헤더에서 IP 부분만 추출
            		if(packet.hasHeader(ip)) {
            			if(tcp.destination() == smtp && FormatUtils.ip(ip.source()).equals("10.10.10.84")) {
            				result.append("============\n");
            				result.append("SMEX -> SMTP\n");
            				System.out.println("SMEX -> SMTP");
            				result.append("시간 = " + nowTime1 + "\n");
            				result.append("출발지 IP 주소 = " + FormatUtils.ip(ip.source()) + "\n도착지 IP 주소  = " + FormatUtils.ip(ip.destination()) + "\n");
            			}
            			else if(tcp.source() == smtp && FormatUtils.ip(ip.destination()).equals("10.10.10.84")) {
            				result.append("============\n");
            				result.append("SMTP -> SMEX\n");
            				System.out.println("SMTP -> SMEX");
            				result.append("시간 = " + nowTime1 + "\n");
            				result.append("출발지 IP 주소 = " + FormatUtils.ip(ip.source()) + "\n도착지 IP 주소  = " + FormatUtils.ip(ip.destination()) + "\n");
            			}
            			System.out.printf("출발지 IP 주소 = %s \n도착지 IP 주소 = %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
            		}
            		System.out.println("시간: " + nowTime1);

            		//패킷의 헤더에서 TCP 부분만 추출(포트 번호)
            		System.out.printf("출발지 TCP 주소 = %s \n도착지 TCP 주소 = %s\n", tcp.source(), tcp.destination());
            		result.append("출발지 TCP 주소 = " + tcp.source() + "\n도착지 TCP 주소 = " + tcp.destination() + "\n");
 
            		//packet.hasHeader(payload) ->이 방식은 packet의 헤더정보에서 payload가 있는지 여부를 확인하는 메소드로 따로 payload가 안잡힘(tcp의 payload에서 가져와야함)
            		
        			byte[] tcp_payloadData = tcp.getPayload();//TCP에 있는 payload 값 가져옴(바이트 형태)
        			String payloadData = DatatypeConverter.printHexBinary(tcp_payloadData);//바이트형태를 문자열형식으로 변환
        			String asciiString = hexToAscii(payloadData);//16진수를 아스키 코드로 변환
        			System.out.println("데이터 : " + asciiString + "\n");
        			if(tcp.getPayload() != null) {
        				result.append("데이터 : " + asciiString + "\n");
        			}

                	try {
						writer.write(result.toString());
						writer.flush(); //버퍼의 남은 데이터를 모두 쓰기
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
                    
                    result.delete(0, result.length());
        		}
    		}
    	}
    	pcap.close();//패킷 캡처 종료
    	System.out.println("SMTP 포트 587 스캔 종료");
    	System.out.println(result.toString());
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
