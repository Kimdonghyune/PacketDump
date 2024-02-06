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
    //16������ �ƽ�Ű�ڵ�� ��ȯ
	private static String hexToAscii(String hexString) {
		StringBuilder output = new StringBuilder();
		//16������ ����� ���� 2���� ���ڿ� �����Ͽ� �ش� ���ڷ� �ƽ�Ű ��ȯ
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
		//��Ʈ��ũ ��� �����ϴ� ������ �Ҵ�
    	ArrayList<PcapIf> allDevs = new ArrayList<PcapIf>();
    	//���� �޼����� ��� ����
    	StringBuilder errbuf = new StringBuilder();
    	
    	int smtp = 587;
    	
    	//��Ʈ��ũ ��� ã�Ƽ� ����, ��Ʈ��ũ ��� ��ã���� return�Ͽ� ����
    	Pcap.findAllDevs(allDevs, errbuf);
    	if(allDevs.isEmpty()) {
    		System.out.println("��Ʈ��ũ ��ġ�� ã�� �� �����ϴ�. ���� : " + errbuf.toString());
    		return;
    	}
    	System.out.println("[ ��Ʈ��ũ ��� Ž�� ���� ]");
    	
    	//ã�� ��� �ϳ��� ���鼭 ���� ���
    	for(int i = 0; i<allDevs.size(); i++) {
    		PcapIf device = allDevs.get(i);
    		String description = (device.getDescription() != null) ? device.getDescription() : "��� ���� ������ �����ϴ�.";
    		System.out.printf("[%d��] : %s [%s]\n", i, device.getName(), description);
    	}
    	
    	//��Ʈ��ũ ��ġ �߿��� �ϳ��� ���� (4�� ���� : �̴���)
    	PcapIf device = allDevs.get(4);
    	System.out.printf("���õ� ��ġ %s \n", (device.getDescription() != null) ? device.getDescription() : device.getName());
    	
    	//65536����Ʈ ��ŭ ��Ŷ ĸó
    	int snaplen = 64 * 1024;
    	
    	//����̽��� ���� ���� - �ش� ��Ʈ��ũ ��ġ�� ������ ��� ��Ŷ ĸó�ϴ� ���
    	int flags = Pcap.MODE_PROMISCUOUS;
    	
    	//Ÿ�� �ƿ��� 30�ʷ� ����
    	int timeout = 30 * 1000;
    	
    	//��ġ�� ��Ŷ ĸó�� Ȱ��ȭ�մϴ�
    	Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
    	
    	//Pcap ��ü�� �������� ������ ���� �޼��� �߻�
    	if(pcap == null) {
    		System.out.println("��Ŷ ĸó�� ���� ��Ʈ��ũ ��ġ�� ���µ� ���� ����: " + errbuf.toString());
    		return;
    	}
    	
    	//IP �ּ� ��ü ����
    	Ip4 ip = new Ip4();
    	
    	//TCP �ּ� ��ü ����
    	Tcp tcp = new Tcp();
    	
    	//ĸó�� ��Ŷ�� ��� ��ü ����
    	PcapHeader header = new PcapHeader(JMemory.POINTER);
    	
    	//��Ŷ ���� ���� ����
    	JBuffer buf = new JBuffer(JMemory.POINTER);
    	
    	//PCAP�� ������ ��ũ Ÿ���� JnetPcap�� �������� ID������ ����
    	int id = JRegistry.mapDLTToId(pcap.datalink());
    	
    	//�ð� ���� ����
    	SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    	
    	String filePath = "C:\\data\\SMTP_Packet_Dump.txt";//�ش� ��ġ�� �ش� ���ϸ����� ���� ����
        File file = new File(filePath); //File��ü ����
        if(!file.exists()){ //������ �������� ������
            try {
				file.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} //�űԻ���
        }

        // BufferedWriter ����
        BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(file, false));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        StringBuffer result = new StringBuffer();
		
        
    	System.out.println("SMTP ��Ʈ "+ smtp + " ��ĵ ����");
    	//������ �߻����� �ʴ� �� ����ؼ� ���� ��Ŷ�� �Է¹���
    	while(pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK) {
    		PcapPacket packet = new PcapPacket(header, buf);
    		packet.scan(id);
    		// TCP(��Ʈ��ȣ)�� 587�̸� SMTP
    		if(packet.hasHeader(tcp)) {
    			byte[] compare_payloadData = tcp.getPayload();//TCP�� �ִ� payload �� ������(����Ʈ ����)
    			String compare_payload = DatatypeConverter.printHexBinary(compare_payloadData);//����Ʈ���¸� ���ڿ��������� ��ȯ
    			String asciiCode = hexToAscii(compare_payload);//16������ �ƽ�Ű �ڵ�� ��ȯ
    			
        		if((tcp.source() == smtp || tcp.destination() == smtp) && asciiCode.length() != 0) {
        			System.out.println("-------------");
        			Date date = new Date(packet.getCaptureHeader().timestampInMillis());
        			String nowTime1 = sdf1.format(date);

        			//��Ŷ�� ������� IP �κи� ����
            		if(packet.hasHeader(ip)) {
            			if(tcp.destination() == smtp && FormatUtils.ip(ip.source()).equals("10.10.10.84")) {
            				result.append("============\n");
            				result.append("SMEX -> SMTP\n");
            				System.out.println("SMEX -> SMTP");
            				result.append("�ð� = " + nowTime1 + "\n");
            				result.append("����� IP �ּ� = " + FormatUtils.ip(ip.source()) + "\n������ IP �ּ�  = " + FormatUtils.ip(ip.destination()) + "\n");
            			}
            			else if(tcp.source() == smtp && FormatUtils.ip(ip.destination()).equals("10.10.10.84")) {
            				result.append("============\n");
            				result.append("SMTP -> SMEX\n");
            				System.out.println("SMTP -> SMEX");
            				result.append("�ð� = " + nowTime1 + "\n");
            				result.append("����� IP �ּ� = " + FormatUtils.ip(ip.source()) + "\n������ IP �ּ�  = " + FormatUtils.ip(ip.destination()) + "\n");
            			}
            			System.out.printf("����� IP �ּ� = %s \n������ IP �ּ� = %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
            		}
            		System.out.println("�ð�: " + nowTime1);

            		//��Ŷ�� ������� TCP �κи� ����(��Ʈ ��ȣ)
            		System.out.printf("����� TCP �ּ� = %s \n������ TCP �ּ� = %s\n", tcp.source(), tcp.destination());
            		result.append("����� TCP �ּ� = " + tcp.source() + "\n������ TCP �ּ� = " + tcp.destination() + "\n");
 
            		//packet.hasHeader(payload) ->�� ����� packet�� ����������� payload�� �ִ��� ���θ� Ȯ���ϴ� �޼ҵ�� ���� payload�� ������(tcp�� payload���� �����;���)
            		
        			byte[] tcp_payloadData = tcp.getPayload();//TCP�� �ִ� payload �� ������(����Ʈ ����)
        			String payloadData = DatatypeConverter.printHexBinary(tcp_payloadData);//����Ʈ���¸� ���ڿ��������� ��ȯ
        			String asciiString = hexToAscii(payloadData);//16������ �ƽ�Ű �ڵ�� ��ȯ
        			System.out.println("������ : " + asciiString + "\n");
        			if(tcp.getPayload() != null) {
        				result.append("������ : " + asciiString + "\n");
        			}

                	try {
						writer.write(result.toString());
						writer.flush(); //������ ���� �����͸� ��� ����
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
                    
                    result.delete(0, result.length());
        		}
    		}
    	}
    	pcap.close();//��Ŷ ĸó ����
    	System.out.println("SMTP ��Ʈ 587 ��ĵ ����");
    	System.out.println(result.toString());
    	try {
			writer.write(result.toString());
	        writer.flush(); //������ ���� �����͸� ��� ����
	        writer.close(); //��Ʈ�� ����
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
